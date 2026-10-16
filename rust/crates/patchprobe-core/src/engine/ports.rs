//! Scan de ports TCP d'un hôte sous le plafond global de connexions, avec backoff quand l'OS
//! manque de ressources.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinSet;

use super::limits::{ConnectionLimiter, ConnectionPermit};
use crate::net::tcp::{TcpConnector, TcpProbe};

/// Nombre maximal de nouvelles tentatives après une erreur de ressources.
pub const MAX_RESOURCE_RETRIES: u32 = 6;

#[derive(Debug, Default)]
pub struct PortScanStats {
    /// Erreurs EMFILE/ENOBUFS/ENOMEM rencontrées (chacune a déclenché un backoff).
    pub exhaustion_events: AtomicU64,
    /// Sondes abandonnées après [`MAX_RESOURCE_RETRIES`] tentatives.
    pub abandoned_probes: AtomicU64,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct PortScanResult {
    pub open_ports: Vec<u16>,
    /// A successful TCP connection or a connection refusal proves the IP responded.
    pub responsive: bool,
}

impl PortScanStats {
    pub fn exhaustion_events(&self) -> u64 {
        self.exhaustion_events.load(Ordering::Relaxed)
    }

    pub fn abandoned_probes(&self) -> u64 {
        self.abandoned_probes.load(Ordering::Relaxed)
    }
}

/// Délai avant la tentative `attempt` (0, 1, …) : exponentiel plafonné à 1 s, avec gigue.
pub fn backoff_delay(attempt: u32) -> Duration {
    let base_ms = 25u64.saturating_mul(1u64 << attempt.min(6)).min(1000);
    let jitter = rand::random::<u64>() % (base_ms / 2 + 1);
    Duration::from_millis(base_ms + jitter)
}

/// Sonde un port en gardant la place dans le plafond pendant les backoffs : sous pression,
/// le nombre réel de sockets en vol diminue donc mécaniquement.
async fn probe_with_backoff(
    connector: Arc<dyn TcpConnector>,
    addr: SocketAddrV4,
    timeout: Duration,
    stats: Arc<PortScanStats>,
    _permit: ConnectionPermit,
) -> TcpProbe {
    let mut attempt = 0;
    loop {
        let result = connector.probe(addr, timeout).await;
        if result != TcpProbe::ResourceExhausted {
            return result;
        }
        stats.exhaustion_events.fetch_add(1, Ordering::Relaxed);
        if attempt >= MAX_RESOURCE_RETRIES {
            stats.abandoned_probes.fetch_add(1, Ordering::Relaxed);
            return result;
        }
        tokio::time::sleep(backoff_delay(attempt)).await;
        attempt += 1;
    }
}

/// Ports ouverts de `ip` parmi `ports`, triés. Chaque connexion prend une place dans le
/// plafond GLOBAL `limiter` (partagé par tous les hôtes). Annuler la future annule toutes les
/// sondes en vol (le `JoinSet` les abandonne, les sockets sont fermés).
pub async fn scan_ports(
    ip: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    limiter: &Arc<ConnectionLimiter>,
    connector: &Arc<dyn TcpConnector>,
    stats: &Arc<PortScanStats>,
) -> PortScanResult {
    let mut result = PortScanResult::default();
    let mut set = JoinSet::new();
    let mut collect = |joined: Result<(u16, TcpProbe), tokio::task::JoinError>| {
        if let Ok((port, probe)) = joined {
            match probe {
                TcpProbe::Open => {
                    result.open_ports.push(port);
                    result.responsive = true;
                }
                TcpProbe::Closed => result.responsive = true,
                TcpProbe::Filtered | TcpProbe::ResourceExhausted | TcpProbe::Error(_) => {}
            }
        }
    };
    for &port in ports {
        let Some(permit) = limiter.acquire().await else { break };
        let task =
            probe_with_backoff(Arc::clone(connector), SocketAddrV4::new(ip, port), timeout, Arc::clone(stats), permit);
        set.spawn(async move { (port, task.await) });
        while let Some(result) = set.try_join_next() {
            collect(result);
        }
    }
    while let Some(result) = set.join_next().await {
        collect(result);
    }
    result.open_ports.sort_unstable();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::AtomicU32;

    struct FlakyConnector {
        failures_left: AtomicU32,
    }

    #[async_trait]
    impl TcpConnector for FlakyConnector {
        async fn probe(&self, addr: SocketAddrV4, _timeout: Duration) -> TcpProbe {
            if addr.port() != 80 {
                return TcpProbe::Closed;
            }
            if self.failures_left.load(Ordering::SeqCst) > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                return TcpProbe::ResourceExhausted;
            }
            TcpProbe::Open
        }
    }

    #[tokio::test(start_paused = true)]
    async fn retries_after_resource_exhaustion() {
        let connector: Arc<dyn TcpConnector> = Arc::new(FlakyConnector { failures_left: AtomicU32::new(3) });
        let stats = Arc::new(PortScanStats::default());
        let limiter = ConnectionLimiter::new(4);
        let result =
            scan_ports(Ipv4Addr::LOCALHOST, &[22, 80, 443], Duration::from_millis(100), &limiter, &connector, &stats)
                .await;
        assert_eq!(result.open_ports, [80]);
        assert!(result.responsive);
        assert_eq!(stats.exhaustion_events(), 3);
        assert_eq!(stats.abandoned_probes(), 0);
        assert_eq!(limiter.in_flight(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn gives_up_after_max_retries() {
        let connector: Arc<dyn TcpConnector> = Arc::new(FlakyConnector { failures_left: AtomicU32::new(100) });
        let stats = Arc::new(PortScanStats::default());
        let result = scan_ports(
            Ipv4Addr::LOCALHOST,
            &[80],
            Duration::from_millis(100),
            &ConnectionLimiter::new(1),
            &connector,
            &stats,
        )
        .await;
        assert!(result.open_ports.is_empty());
        assert!(!result.responsive);
        assert_eq!(stats.abandoned_probes(), 1);
        assert_eq!(stats.exhaustion_events(), u64::from(MAX_RESOURCE_RETRIES) + 1);
    }

    #[test]
    fn backoff_is_bounded() {
        for attempt in 0..20 {
            let delay = backoff_delay(attempt);
            assert!(delay >= Duration::from_millis(25) && delay <= Duration::from_millis(1500));
        }
    }
}
