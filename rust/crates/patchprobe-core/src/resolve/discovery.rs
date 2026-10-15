//! Découverte active de fin de scan : browse Bonjour (mDNS-SD) et SSDP/UPnP — port de
//! `BonjourDiscoveryService.swift` et `SSDPDiscoveryService.swift`.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::proto::ssdp;

/// Types de services parcourus (liste de la version Swift).
pub const BONJOUR_SERVICE_TYPES: [&str; 16] = [
    "_device-info._tcp.local.",
    "_companion-link._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_ssh._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_homekit._tcp.local.",
    "_http._tcp.local.",
    "_printer._tcp.local.",
    "_workstation._tcp.local.",
    "_sftp-ssh._tcp.local.",
];

/// Nettoie un nom d'instance Bonjour : préfixe RAOP `XXXXXXXXXXXX@` (12 hex) et suffixe
/// `_workstation` ` [aa:bb:…]` retirés.
pub fn cleaned_bonjour_name(raw: &str) -> String {
    let mut name = raw;
    if let Some((prefix, rest)) = name.split_once('@') {
        if prefix.len() == 12 && prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            name = rest;
        }
    }
    if let Some(open) = name.rfind(" [") {
        let suffix = name.get(open + 2..).unwrap_or_default();
        if let Some(inner) = suffix.strip_suffix(']') {
            if !inner.is_empty() && inner.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
                name = name.get(..open).unwrap_or(name);
            }
        }
    }
    name.to_owned()
}

/// Nom d'instance à partir du nom complet `Instance._type._tcp.local.`.
pub fn instance_name(fullname: &str, service_type: &str) -> String {
    fullname.strip_suffix(service_type).map(|s| s.trim_end_matches('.')).unwrap_or(fullname).replace("\\032", " ")
}

/// Browse Bonjour pendant `budget` ; premier nom trouvé par IP.
pub async fn bonjour(budget: Duration) -> HashMap<Ipv4Addr, String> {
    let Ok(daemon) = mdns_sd::ServiceDaemon::new() else {
        return HashMap::new();
    };
    let found: Arc<Mutex<HashMap<Ipv4Addr, String>>> = Arc::default();
    let deadline = tokio::time::Instant::now() + budget;
    let mut tasks = tokio::task::JoinSet::new();
    for service_type in BONJOUR_SERVICE_TYPES {
        let Ok(receiver) = daemon.browse(service_type) else { continue };
        let found = Arc::clone(&found);
        tasks.spawn(async move {
            while let Ok(Ok(event)) = tokio::time::timeout_at(deadline, receiver.recv_async()).await {
                let mdns_sd::ServiceEvent::ServiceResolved(info) = event else { continue };
                let name = cleaned_bonjour_name(&instance_name(info.get_fullname(), service_type));
                let Some(name) = crate::proto::sanitize_name(&name) else { continue };
                if let Ok(mut map) = found.lock() {
                    for ip in info.get_addresses_v4() {
                        map.entry(*ip).or_insert_with(|| name.clone());
                    }
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    let _ = daemon.shutdown();
    let result = found.lock().map(|map| map.clone()).unwrap_or_default();
    result
}

/// M-SEARCH SSDP puis `friendlyName` de chaque descripteur (hôte = l'appareil qui a répondu).
pub async fn ssdp(budget: Duration, client: Option<&reqwest::Client>) -> HashMap<Ipv4Addr, String> {
    let locations = collect_ssdp_locations(budget).await;
    let Some(client) = client else { return HashMap::new() };
    let mut tasks = tokio::task::JoinSet::new();
    for (ip, location) in locations {
        let client = client.clone();
        tasks.spawn(async move {
            let response = client.get(&location).timeout(Duration::from_millis(1500)).send().await.ok()?;
            let body = super::techniques::read_limited(response, 64 * 1024).await;
            ssdp::extract_friendly_name(&String::from_utf8_lossy(&body)).map(|name| (ip, name))
        });
    }
    let mut names = HashMap::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some((ip, name))) = result {
            names.insert(ip, name);
        }
    }
    names
}

async fn collect_ssdp_locations(budget: Duration) -> HashMap<Ipv4Addr, String> {
    let mut locations = HashMap::new();
    let Ok(socket) = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await else {
        return locations;
    };
    let _ = socket.set_multicast_ttl_v4(2);
    let target = SocketAddrV4::new(ssdp::MULTICAST_ADDR, ssdp::PORT);
    if socket.send_to(ssdp::m_search_request(), target).await.is_err() {
        return locations;
    }
    let deadline = tokio::time::Instant::now() + budget;
    let mut buffer = vec![0u8; 2048];
    while let Ok(received) = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await {
        let Ok((len, std::net::SocketAddr::V4(from))) = received else { continue };
        let text = String::from_utf8_lossy(buffer.get(..len).unwrap_or_default()).into_owned();
        if let Some(location) = ssdp::header(&text, "LOCATION").and_then(|l| ssdp::validated_location(l, *from.ip())) {
            locations.entry(*from.ip()).or_insert(location);
        }
    }
    locations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_cleanup_vectors() {
        assert_eq!(cleaned_bonjour_name("020000000008@test-desktop"), "test-desktop");
        assert_eq!(cleaned_bonjour_name("desktop-01 [02:00:00:00:00:07]"), "desktop-01");
        assert_eq!(cleaned_bonjour_name("media-device-1"), "media-device-1");
        assert_eq!(cleaned_bonjour_name("test-phone"), "test-phone");
        assert_eq!(cleaned_bonjour_name("user@printer"), "user@printer");
        assert_eq!(cleaned_bonjour_name("printer [test]"), "printer [test]");
    }

    #[test]
    fn instance_name_strips_service_type() {
        assert_eq!(instance_name("media-device-1._airplay._tcp.local.", "_airplay._tcp.local."), "media-device-1");
        assert_eq!(instance_name("weird", "_http._tcp.local."), "weird");
    }

    #[tokio::test]
    async fn discovery_without_network_returns_quickly() {
        let started = std::time::Instant::now();
        let _ = ssdp(Duration::from_millis(200), None).await;
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
