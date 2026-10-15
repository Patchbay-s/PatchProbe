//! Scan UDP avec vraie distinction ouvert / fermé / ouvert|filtré — port de
//! `UDPPortScanner.swift`.
//!
//! - ouvert : une réponse protocolaire est revenue ;
//! - fermé : l'OS a remonté l'ICMP « port injoignable » sur le socket connecté (ECONNREFUSED,
//!   WSAECONNRESET sous Windows), sans socket brut ni privilèges ;
//! - ouvert|filtré : rien avant le délai (service muet ou pare-feu), ambiguïté inhérente à l'UDP.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::proto::{dns, nbns, snmp, ssdp};
use crate::resolve::techniques::{udp_request, UdpError};

pub const DEFAULT_UDP_PORTS: [u16; 9] = [53, 67, 69, 123, 137, 161, 500, 1900, 5353];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UdpPortStatus {
    Open,
    Closed,
    OpenOrFiltered,
}

impl UdpPortStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Open => "ouvert",
            Self::Closed => "fermé",
            Self::OpenOrFiltered => "ouvert|filtré",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UdpPortResult {
    pub port: u16,
    pub service: Option<String>,
    pub status: UdpPortStatus,
}

pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        53 => "dns",
        67 => "dhcp",
        69 => "tftp",
        123 => "ntp",
        137 => "netbios-ns",
        161 => "snmp",
        500 => "isakmp",
        1900 => "ssdp",
        5353 => "mdns",
        _ => return None,
    })
}

/// Requête client NTP v4.
pub fn ntp_client_request() -> Vec<u8> {
    let mut packet = vec![0u8; 48];
    if let Some(first) = packet.first_mut() {
        *first = 0x23; // LI=0, VN=4, Mode=3
    }
    packet
}

/// Charge utile qui provoque une réponse du service, sinon un octet nul.
pub fn probe_payload(port: u16) -> Vec<u8> {
    match port {
        53 => dns::root_ns_query(),
        123 => ntp_client_request(),
        137 => nbns::build_nbstat_query(0x4950),
        161 => snmp::build_get_request(snmp::OID_SYS_DESCR, "public", 1),
        1900 => ssdp::m_search_request().to_vec(),
        5353 => dns::build_ptr_query(Ipv4Addr::LOCALHOST, 0, false),
        _ => vec![0x00],
    }
}

pub async fn scan_port(ip: Ipv4Addr, port: u16, timeout: Duration) -> UdpPortStatus {
    match udp_request(SocketAddrV4::new(ip, port), &probe_payload(port), timeout, |_| true).await {
        Ok(_) => UdpPortStatus::Open,
        Err(UdpError::PortClosed) => UdpPortStatus::Closed,
        Err(UdpError::Timeout | UdpError::Io(_)) => UdpPortStatus::OpenOrFiltered,
    }
}

/// Sonde `ports` (au plus `max_concurrency` en vol) ; résultats triés par port. Annuler la
/// future abandonne toutes les sondes.
pub async fn scan_ports(ip: Ipv4Addr, ports: &[u16], timeout: Duration, max_concurrency: usize) -> Vec<UdpPortResult> {
    let mut results = Vec::with_capacity(ports.len());
    let mut set = JoinSet::new();
    let mut pending = ports.iter().copied();
    loop {
        while set.len() < max_concurrency.max(1) {
            let Some(port) = pending.next() else { break };
            set.spawn(async move { (port, scan_port(ip, port, timeout).await) });
        }
        match set.join_next().await {
            Some(Ok((port, status))) => {
                results.push(UdpPortResult { port, service: service_name(port).map(str::to_owned), status });
            }
            Some(Err(_)) => {}
            None => break,
        }
    }
    results.sort_unstable_by_key(|r| r.port);
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[test]
    fn swift_vectors() {
        assert_eq!(service_name(53), Some("dns"));
        assert_eq!(service_name(123), Some("ntp"));
        assert_eq!(service_name(161), Some("snmp"));
        assert_eq!(service_name(1900), Some("ssdp"));
        assert_eq!(service_name(40125), None);
        let dns = dns::root_ns_query();
        assert_eq!(dns.len(), 17);
        let ntp = ntp_client_request();
        assert_eq!(ntp.len(), 48);
        assert_eq!(ntp[0], 0x23);
        assert!(ntp[1..].iter().all(|b| *b == 0));
        assert_eq!(probe_payload(53), dns);
        assert_eq!(probe_payload(123), ntp);
        assert_eq!(probe_payload(40125), [0x00]);
        let snmp = probe_payload(161);
        assert!(snmp.windows(8).any(|w| w == [0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00]));
        assert!(
            DEFAULT_UDP_PORTS.contains(&53) && DEFAULT_UDP_PORTS.contains(&123) && DEFAULT_UDP_PORTS.contains(&161)
        );
    }

    #[tokio::test]
    async fn open_closed_and_filtered_on_loopback() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let open_port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..len], from).await;
            }
        });
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let silent_port = silent.local_addr().unwrap().port();
        let closed_port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();

        let results =
            scan_ports(Ipv4Addr::LOCALHOST, &[closed_port, open_port, silent_port], Duration::from_millis(300), 8)
                .await;
        let status = |port: u16| results.iter().find(|r| r.port == port).unwrap().status;
        assert_eq!(status(open_port), UdpPortStatus::Open);
        assert_eq!(status(closed_port), UdpPortStatus::Closed);
        assert_eq!(status(silent_port), UdpPortStatus::OpenOrFiltered);
        drop(silent);
        assert!(scan_ports(Ipv4Addr::LOCALHOST, &[], Duration::from_millis(10), 8).await.is_empty());
    }
}
