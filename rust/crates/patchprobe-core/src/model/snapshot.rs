//! Snapshot d'historique — port de `ScanSnapshot.swift`.

use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::host::{Host, HostStatus};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSnapshot {
    pub ip: Ipv4Addr,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub latency_ms: Option<f64>,
    #[serde(default)]
    pub open_ports: Vec<u16>,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub vendor: Option<String>,
    #[serde(default)]
    pub probable_os: Option<String>,
}

impl HostSnapshot {
    pub fn from_host(host: &Host) -> Self {
        Self {
            ip: host.ip,
            hostname: host.hostname.clone(),
            latency_ms: host.latency_ms,
            open_ports: host.open_ports.clone(),
            mac: host.mac.clone(),
            vendor: host.vendor.clone(),
            probable_os: host.probable_os.clone(),
        }
    }

    /// Recharge dans la table sans toucher au réseau : un hôte sauvegardé était actif.
    pub fn to_host(&self) -> Host {
        let mut host = Host::new(self.ip);
        host.hostname = self.hostname.clone();
        host.status = HostStatus::Up;
        host.latency_ms = self.latency_ms;
        host.open_ports = self.open_ports.clone();
        host.mac = self.mac.clone();
        host.vendor = self.vendor.clone();
        host.probable_os = self.probable_os.clone();
        host.refresh_derived();
        host
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanSnapshot {
    pub id: Uuid,
    pub date: DateTime<Utc>,
    pub range_input: String,
    pub hosts: Vec<HostSnapshot>,
}

impl ScanSnapshot {
    /// Ne garde que les hôtes actifs ; `None` s'il n'y en a aucun (rien à historiser).
    pub fn from_scan(range_input: &str, hosts: &[Host], date: DateTime<Utc>) -> Option<Self> {
        let live: Vec<HostSnapshot> =
            hosts.iter().filter(|h| h.status == HostStatus::Up).map(HostSnapshot::from_host).collect();
        if live.is_empty() {
            return None;
        }
        Some(Self { id: Uuid::new_v4(), date, range_input: range_input.to_owned(), hosts: live })
    }

    /// Hôtes rechargeables, sans doublon d'IP (premier conservé) même si le fichier en contient.
    pub fn to_hosts(&self) -> Vec<Host> {
        let mut seen = std::collections::HashSet::new();
        self.hosts.iter().filter(|h| seen.insert(h.ip)).map(HostSnapshot::to_host).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_only_live_hosts_and_dedupes_on_load() {
        let mut up = Host::new(Ipv4Addr::new(198, 51, 100, 1));
        up.status = HostStatus::Up;
        let down = Host::new(Ipv4Addr::new(198, 51, 100, 2));
        let mut snap = ScanSnapshot::from_scan("198.51.100.0/24", &[up.clone(), down], Utc::now()).unwrap();
        assert_eq!(snap.hosts.len(), 1);
        snap.hosts.push(snap.hosts[0].clone());
        assert_eq!(snap.to_hosts().len(), 1);
        assert!(ScanSnapshot::from_scan("x", &[Host::new(Ipv4Addr::LOCALHOST)], Utc::now()).is_none());
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let json = r#"{"id":"5b1f6c2e-8d1e-4a59-9a43-0c6c7f0d9a11","date":"2026-01-01T00:00:00Z",
            "rangeInput":"198.51.100.0/24","hosts":[{"ip":"198.51.100.1"}]}"#;
        let snap: ScanSnapshot = serde_json::from_str(json).unwrap();
        assert_eq!(snap.hosts[0].open_ports, Vec::<u16>::new());
    }
}
