//! Profil de site (inventaire attendu) — port de `SiteProfile.swift`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::host::{Host, HostStatus};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfileEntry {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub label: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub mac: Option<String>,
}

impl SiteProfileEntry {
    pub fn new(label: impl Into<String>, ip: Option<&str>, mac: Option<&str>) -> Self {
        Self { id: Uuid::new_v4(), label: label.into(), ip: ip.map(str::to_owned), mac: mac.map(str::to_owned) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfile {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub entries: Vec<SiteProfileEntry>,
}

impl SiteProfile {
    pub fn new(name: impl Into<String>, entries: Vec<SiteProfileEntry>) -> Self {
        Self { id: Uuid::new_v4(), name: name.into(), entries }
    }

    /// Création en un clic à partir des hôtes actifs du scan (label = hostname, sinon IP).
    pub fn from_hosts(name: impl Into<String>, hosts: &[Host]) -> Self {
        let entries = hosts
            .iter()
            .filter(|h| h.status == HostStatus::Up)
            .map(|h| SiteProfileEntry {
                id: Uuid::new_v4(),
                label: h.hostname.clone().unwrap_or_else(|| h.ip.to_string()),
                ip: Some(h.ip.to_string()),
                mac: h.mac.clone(),
            })
            .collect();
        Self::new(name, entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codable_round_trip() {
        let profile = SiteProfile::new(
            "Site",
            vec![SiteProfileEntry::new("Test camera", Some("192.0.2.10"), Some("02:00:00:00:00:01"))],
        );
        let json = serde_json::to_string(&profile).unwrap();
        assert_eq!(serde_json::from_str::<SiteProfile>(&json).unwrap(), profile);
    }

    #[test]
    fn from_hosts_uses_live_hosts_only() {
        let mut up = Host::new("198.51.100.1".parse().unwrap());
        up.status = HostStatus::Up;
        up.hostname = Some("nas".into());
        let down = Host::new("198.51.100.2".parse().unwrap());
        let profile = SiteProfile::from_hosts("Test site", &[up, down]);
        assert_eq!(profile.entries.len(), 1);
        assert_eq!(profile.entries[0].label, "nas");
        assert_eq!(profile.entries[0].ip.as_deref(), Some("198.51.100.1"));
    }
}
