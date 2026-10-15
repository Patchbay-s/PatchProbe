//! Sonde TCP connect avec timeout et classification des erreurs (dont l'épuisement de
//! ressources de l'OS, qui déclenche un backoff dans le moteur).

use std::io;
use std::net::SocketAddrV4;
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpProbe {
    /// Connexion établie : port ouvert.
    Open,
    /// RST reçu : port fermé (l'hôte est joignable).
    Closed,
    /// Pas de réponse avant le délai : filtré ou hôte absent.
    Filtered,
    /// L'OS manque de descripteurs/tampons/mémoire (EMFILE, ENFILE, ENOBUFS, ENOMEM).
    ResourceExhausted,
    /// Autre erreur (réseau injoignable…).
    Error(String),
}

/// Établit une connexion TCP : implémentation réelle (tokio) ou factice en test.
#[async_trait]
pub trait TcpConnector: Send + Sync + 'static {
    async fn probe(&self, addr: SocketAddrV4, timeout: Duration) -> TcpProbe;
}

/// Connecteur réel basé sur `tokio::net::TcpStream`. Le socket est fermé dès la sonde finie
/// (drop), y compris si la future est annulée.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioConnector;

#[async_trait]
impl TcpConnector for TokioConnector {
    async fn probe(&self, addr: SocketAddrV4, timeout: Duration) -> TcpProbe {
        match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            Err(_) => TcpProbe::Filtered,
            Ok(Ok(_stream)) => TcpProbe::Open,
            Ok(Err(error)) => classify_connect_error(&error),
        }
    }
}

pub fn classify_connect_error(error: &io::Error) -> TcpProbe {
    if is_resource_exhaustion(error) {
        return TcpProbe::ResourceExhausted;
    }
    match error.kind() {
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => TcpProbe::Closed,
        io::ErrorKind::TimedOut => TcpProbe::Filtered,
        _ => TcpProbe::Error(error.to_string()),
    }
}

#[cfg(target_os = "linux")]
const RESOURCE_ERRNOS: &[i32] =
    &[24 /* EMFILE */, 23 /* ENFILE */, 105 /* ENOBUFS */, 12 /* ENOMEM */];
#[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
const RESOURCE_ERRNOS: &[i32] =
    &[24 /* EMFILE */, 23 /* ENFILE */, 55 /* ENOBUFS */, 12 /* ENOMEM */];
#[cfg(windows)]
const RESOURCE_ERRNOS: &[i32] = &[
    10024, // WSAEMFILE
    10055, // WSAENOBUFS
    8,     // ERROR_NOT_ENOUGH_MEMORY
    14,    // ERROR_OUTOFMEMORY
];
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    windows
)))]
const RESOURCE_ERRNOS: &[i32] = &[24, 23, 12];

/// Vrai pour les erreurs qui signalent un manque de ressources local plutôt qu'un état du port.
pub fn is_resource_exhaustion(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::OutOfMemory
        || error.raw_os_error().is_some_and(|code| RESOURCE_ERRNOS.contains(&code))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn open_and_closed_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
        assert_eq!(TokioConnector.probe(addr, Duration::from_secs(1)).await, TcpProbe::Open);
        drop(listener);
        // Windows réessaie le SYN après un RST : le refus arrive en ~2 s, d'où le délai large.
        assert_eq!(TokioConnector.probe(addr, Duration::from_secs(5)).await, TcpProbe::Closed);
    }

    #[test]
    fn classifies_resource_errors() {
        let first = RESOURCE_ERRNOS[0];
        assert!(is_resource_exhaustion(&io::Error::from_raw_os_error(first)));
        assert_eq!(classify_connect_error(&io::Error::from_raw_os_error(first)), TcpProbe::ResourceExhausted);
        assert!(!is_resource_exhaustion(&io::Error::from(io::ErrorKind::ConnectionRefused)));
        assert_eq!(classify_connect_error(&io::Error::from(io::ErrorKind::ConnectionRefused)), TcpProbe::Closed);
    }
}
