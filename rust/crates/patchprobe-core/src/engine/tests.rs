use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::net::tcp::{TcpProbe, TokioConnector};
use crate::resolve::types::{NoNameResolution, Outcome, TechniqueResult};

#[derive(Default)]
struct MockSystem {
    alive: HashSet<Ipv4Addr>,
    macs: HashMap<Ipv4Addr, String>,
    arp: Mutex<HashMap<Ipv4Addr, String>>,
    pings: AtomicUsize,
}

#[async_trait]
impl SystemProbe for MockSystem {
    async fn ping(&self, ip: Ipv4Addr, _timeout: Duration) -> PingReply {
        self.pings.fetch_add(1, Ordering::SeqCst);
        if self.alive.contains(&ip) {
            PingReply { alive: true, latency_ms: Some(1.5), ttl: Some(64) }
        } else {
            PingReply::default()
        }
    }

    async fn arp_lookup(&self, ip: Ipv4Addr) -> Option<String> {
        self.macs.get(&ip).cloned()
    }

    async fn arp_table(&self) -> HashMap<Ipv4Addr, String> {
        self.arp.lock().unwrap().clone()
    }
}

/// Connecteur factice : chaque sonde dure `delay` et compte la concurrence réelle.
struct SlowConnector {
    delay: Duration,
    open: HashSet<u16>,
    current: AtomicUsize,
    peak: AtomicUsize,
}

struct Guard<'a>(&'a AtomicUsize);
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl TcpConnector for SlowConnector {
    async fn probe(&self, addr: SocketAddrV4, _timeout: Duration) -> TcpProbe {
        let now = self.current.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        let _guard = Guard(&self.current);
        tokio::time::sleep(self.delay).await;
        if self.open.contains(&addr.port()) {
            TcpProbe::Open
        } else {
            TcpProbe::Closed
        }
    }
}

fn request(range: &str, ports: Vec<u16>, settings: ScanSettings) -> ScanRequest {
    ScanRequest {
        scan_id: 7,
        range: ScanRange::parse(range).unwrap(),
        ports,
        settings,
        vendors: VendorLookup::default(),
    }
}

fn deps(system: Arc<MockSystem>, connector: Arc<dyn TcpConnector>, names: Arc<dyn NameResolution>) -> ScanDeps {
    ScanDeps { system, names, connector }
}

async fn drain(mut rx: mpsc::Receiver<ScanEvent>) -> Vec<ScanEvent> {
    let mut events = Vec::new();
    while let Some(event) = rx.recv().await {
        events.push(event);
    }
    events
}

fn no_discovery() -> ScanSettings {
    ScanSettings { runs_active_discovery: false, runs_arp_sweep: false, ..ScanSettings::approfondi() }
}

#[tokio::test]
async fn open_port_proves_presence_without_ping() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let system = Arc::new(MockSystem::default());
    let (tx, rx) = mpsc::channel(1024);
    let outcome = run_scan(
        request("127.0.0.1", vec![port], no_discovery()),
        deps(system, Arc::new(TokioConnector), Arc::new(NoNameResolution)),
        tx,
        CancellationToken::new(),
    )
    .await;
    let host = &outcome.hosts[0];
    assert_eq!(host.status, HostStatus::Up);
    assert_eq!(host.open_ports, [port]);
    assert_eq!(host.ttl, None, "pas de TTL sans réponse ping");
    let events = drain(rx).await;
    assert!(matches!(events.first(), Some(ScanEvent::Started { total: 1, .. })));
    assert!(matches!(events.last(), Some(ScanEvent::Finished { cancelled: false, up: 1, .. })));
}

#[tokio::test]
async fn refused_tcp_port_proves_presence_without_ping() {
    let connector = Arc::new(SlowConnector {
        delay: Duration::ZERO,
        open: HashSet::new(),
        current: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let (tx, rx) = mpsc::channel(1024);
    let outcome = run_scan(
        request("198.51.100.10", vec![443], no_discovery()),
        deps(Arc::new(MockSystem::default()), connector, Arc::new(NoNameResolution)),
        tx,
        CancellationToken::new(),
    )
    .await;
    let host = &outcome.hosts[0];
    assert_eq!(host.status, HostStatus::Up);
    assert!(host.open_ports.is_empty(), "un port refusé ne doit pas être listé comme ouvert");
    assert!(drain(rx).await.iter().any(|event| matches!(event, ScanEvent::Finished { up: 1, .. })));
}

#[tokio::test]
async fn global_tcp_cap_is_shared_by_all_hosts() {
    let connector = Arc::new(SlowConnector {
        delay: Duration::from_millis(5),
        open: HashSet::new(),
        current: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let settings = ScanSettings { max_tcp_connections: 16, max_parallel_hosts: 10, ..no_discovery() };
    let (tx, rx) = mpsc::channel(4096);
    let drain_task = tokio::spawn(drain(rx));
    let outcome = run_scan(
        request("198.51.100.1-20", (1..=40).collect(), settings),
        deps(Arc::new(MockSystem::default()), connector.clone(), Arc::new(NoNameResolution)),
        tx,
        CancellationToken::new(),
    )
    .await;
    drain_task.await.unwrap();
    let peak = connector.peak.load(Ordering::SeqCst);
    assert!(peak <= 16, "pic {peak} > plafond");
    assert!(peak >= 10, "le plafond devrait être atteint (pic {peak})");
    assert_eq!(outcome.stats.peak_tcp_connections, peak);
    assert!(outcome.hosts.iter().all(|h| h.status == HostStatus::Up));
}

#[tokio::test]
async fn streams_hosts_progress_and_no_host_warning() {
    let mut system = MockSystem::default();
    system.alive.insert(Ipv4Addr::new(198, 51, 100, 2));
    system.macs.insert(Ipv4Addr::new(198, 51, 100, 2), "0:50:56:0:0:1".into());
    let (tx, rx) = mpsc::channel(1024);
    let outcome = run_scan(
        request("198.51.100.1-3", vec![], no_discovery()),
        deps(Arc::new(system), Arc::new(TokioConnector), Arc::new(NoNameResolution)),
        tx,
        CancellationToken::new(),
    )
    .await;
    let up = &outcome.hosts[1];
    assert_eq!(up.status, HostStatus::Up);
    assert_eq!(up.mac.as_deref(), Some("00:50:56:00:00:01"));
    assert_eq!(up.vendor.as_deref(), Some("VMware, Inc."));
    assert_eq!(up.probable_os.as_deref(), Some("Linux/macOS"));
    assert_eq!(up.latency_ms, Some(1.5));
    let events = drain(rx).await;
    let progress: Vec<u64> = events
        .iter()
        .filter_map(|e| match e {
            ScanEvent::Progress { scanned, .. } => Some(*scanned),
            _ => None,
        })
        .collect();
    assert_eq!(progress, [1, 2, 3]);
    assert_eq!(events.iter().filter(|e| matches!(e, ScanEvent::Host { .. })).count(), 3);
    assert!(!events.iter().any(|e| matches!(e, ScanEvent::Warning { .. })));

    // Plage sans aucun hôte vivant : avertissement.
    let (tx, rx) = mpsc::channel(1024);
    run_scan(
        request("198.51.100.1-3", vec![], no_discovery()),
        deps(Arc::new(MockSystem::default()), Arc::new(TokioConnector), Arc::new(NoNameResolution)),
        tx,
        CancellationToken::new(),
    )
    .await;
    assert!(drain(rx)
        .await
        .iter()
        .any(|e| matches!(e, ScanEvent::Warning { message, .. } if message == NO_HOST_WARNING)));
}

#[tokio::test]
async fn cancellation_stops_everything_promptly() {
    let connector = Arc::new(SlowConnector {
        delay: Duration::from_secs(3600),
        open: HashSet::new(),
        current: AtomicUsize::new(0),
        peak: AtomicUsize::new(0),
    });
    let cancel = CancellationToken::new();
    let (tx, rx) = mpsc::channel(4096);
    let drain_task = tokio::spawn(drain(rx));
    let scan = tokio::spawn(run_scan(
        request("198.51.100.0/24", (1..=100).collect(), no_discovery()),
        deps(Arc::new(MockSystem::default()), connector.clone(), Arc::new(NoNameResolution)),
        tx,
        cancel.clone(),
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(connector.current.load(Ordering::SeqCst) > 0);
    cancel.cancel();
    let outcome = tokio::time::timeout(Duration::from_secs(2), scan).await.unwrap().unwrap();
    assert!(outcome.cancelled);
    // Toutes les sondes en vol ont été abandonnées (futures détruites → sockets fermés).
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(connector.current.load(Ordering::SeqCst), 0);
    let events = drain_task.await.unwrap();
    assert!(matches!(events.last(), Some(ScanEvent::Finished { cancelled: true, .. })));
}

/// Résolveur factice qui trouve un nom instantanément.
struct InstantNames;

#[async_trait]
impl NameResolution for InstantNames {
    async fn resolve(&self, ip: Ipv4Addr, _open_ports: &[u16], _mode: ResolveMode) -> NameTrace {
        let mut trace = NameTrace::new(ip);
        trace.push(TechniqueResult::new(
            TechniqueId::Nbns,
            Outcome::Found(format!("host-{}", ip.octets()[3])),
            Duration::ZERO,
        ));
        trace.choose();
        trace
    }

    async fn discover(&self) -> HashMap<Ipv4Addr, (String, TechniqueId)> {
        HashMap::from([(Ipv4Addr::new(198, 51, 100, 2), ("media-device-1".to_owned(), TechniqueId::Ssdp))])
    }
}

#[tokio::test]
async fn name_resolution_is_not_starved_by_saturated_port_scan() {
    // Un seul jeton TCP, monopolisé indéfiniment par l'hôte .2 ; l'hôte .1 (sondé en premier)
    // doit pourtant obtenir son nom.
    struct HangOnSecond;
    #[async_trait]
    impl TcpConnector for HangOnSecond {
        async fn probe(&self, addr: SocketAddrV4, _timeout: Duration) -> TcpProbe {
            if addr.ip().octets()[3] == 2 {
                std::future::pending::<()>().await;
            }
            TcpProbe::Closed
        }
    }
    let mut system = MockSystem::default();
    system.alive.insert(Ipv4Addr::new(198, 51, 100, 1));
    let settings = ScanSettings { max_tcp_connections: 1, ..no_discovery() };
    let cancel = CancellationToken::new();
    let (tx, mut rx) = mpsc::channel(1024);
    let scan = tokio::spawn(run_scan(
        request("198.51.100.1-2", vec![80], settings),
        deps(Arc::new(system), Arc::new(HangOnSecond), Arc::new(InstantNames)),
        tx,
        cancel.clone(),
    ));
    let trace = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match rx.recv().await {
                Some(ScanEvent::NameTrace { trace, .. }) => break trace,
                Some(_) => {}
                None => panic!("canal fermé sans trace"),
            }
        }
    })
    .await
    .expect("la résolution de nom ne doit pas attendre le scan de ports");
    assert_eq!(trace.chosen.unwrap().name, "host-1");
    cancel.cancel();
    assert!(scan.await.unwrap().cancelled);
}

#[tokio::test]
async fn arp_sweep_promotes_and_discovery_names() {
    let mut system = MockSystem::default();
    system.alive.insert(Ipv4Addr::new(198, 51, 100, 2));
    // .3 ne répond ni au ping ni sur un port, mais est dans la table ARP.
    system.arp.lock().unwrap().insert(Ipv4Addr::new(198, 51, 100, 3), "02:00:00:00:00:01".into());
    system.arp.lock().unwrap().insert(Ipv4Addr::new(192, 0, 2, 9), "02:00:00:00:00:02".into());
    let system = Arc::new(system);

    struct NoNamesButDiscovery;
    #[async_trait]
    impl NameResolution for NoNamesButDiscovery {
        async fn resolve(&self, ip: Ipv4Addr, _p: &[u16], _m: ResolveMode) -> NameTrace {
            NameTrace::new(ip)
        }
        async fn discover(&self) -> HashMap<Ipv4Addr, (String, TechniqueId)> {
            InstantNames.discover().await
        }
    }
    let mut overrides = HashMap::new();
    overrides.insert("02-00-00-00-00-01".to_owned(), "Test smart plug".to_owned());
    let mut req = request("198.51.100.1-3", vec![], ScanSettings::approfondi());
    req.vendors = VendorLookup::new(&overrides);
    let (tx, rx) = mpsc::channel(1024);
    let outcome = run_scan(
        req,
        deps(system.clone(), Arc::new(TokioConnector), Arc::new(NoNamesButDiscovery)),
        tx,
        CancellationToken::new(),
    )
    .await;
    drain(rx).await;
    let promoted = &outcome.hosts[2];
    assert_eq!(promoted.status, HostStatus::Up);
    assert_eq!(promoted.vendor.as_deref(), Some("Test smart plug"));
    assert!(promoted.vendor_overridden);
    let named = &outcome.hosts[1];
    assert_eq!(named.hostname.as_deref(), Some("media-device-1"));
    assert_eq!(named.hostname_source.as_deref(), Some("ssdp"));
    let trace = &outcome.traces[&Ipv4Addr::new(198, 51, 100, 2)];
    assert_eq!(trace.chosen.as_ref().unwrap().technique, TechniqueId::Ssdp);
    // 3 pings initiaux + re-ping de .2 (vivant sans MAC) pendant la 2e passe.
    assert_eq!(system.pings.load(Ordering::SeqCst), 4);
}
