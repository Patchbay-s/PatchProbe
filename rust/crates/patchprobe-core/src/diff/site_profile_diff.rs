//! Comparaison profil de site ↔ scan courant — port de `SiteProfileDiff.swift`.
//!
//! La MAC prime sur l'IP (le DHCP change les IP, pas les MAC) : c'est ce qui rend possible la
//! catégorie « Écart » (même appareil, IP différente).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::model::host::Host;
use crate::model::site_profile::{SiteProfile, SiteProfileEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SiteProfileMatchKind {
    /// Conforme.
    Matched,
    /// Écart : même appareil (MAC), IP différente.
    Mismatch,
    /// Manquant.
    Missing,
    /// Inattendu : hôte du scan non réclamé par une entrée.
    Unexpected,
}

impl SiteProfileMatchKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Matched => "Conformes",
            Self::Mismatch => "Écarts",
            Self::Missing => "Manquants",
            Self::Unexpected => "Inattendus",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfileDiffEntry {
    pub id: String,
    pub kind: SiteProfileMatchKind,
    pub entry: Option<SiteProfileEntry>,
    pub host: Option<Host>,
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteProfileDiff {
    pub profile: SiteProfile,
    pub entries: Vec<SiteProfileDiffEntry>,
}

fn non_empty(value: Option<&String>) -> Option<&str> {
    value.map(|v| v.trim()).filter(|v| !v.is_empty())
}

impl SiteProfileDiff {
    pub fn compute(profile: &SiteProfile, hosts: &[Host]) -> Self {
        let mut hosts_by_mac: HashMap<String, &Host> = HashMap::new();
        let mut hosts_by_ip: HashMap<Ipv4Addr, &Host> = HashMap::new();
        for host in hosts {
            if let Some(mac) = host.mac.as_deref() {
                hosts_by_mac.entry(mac.to_lowercase()).or_insert(host);
            }
            hosts_by_ip.entry(host.ip).or_insert(host);
        }

        let mut claimed: HashSet<Ipv4Addr> = HashSet::new();
        let mut entries = Vec::new();
        for entry in &profile.entries {
            let id = entry.id.to_string();
            let mac = non_empty(entry.mac.as_ref()).map(str::to_lowercase);
            let expected_ip = non_empty(entry.ip.as_ref());

            if let Some(host) = mac.as_ref().and_then(|m| hosts_by_mac.get(m)) {
                claimed.insert(host.ip);
                let host_ip = host.ip.to_string();
                let (kind, changes) = match expected_ip {
                    Some(expected) if expected != host_ip => {
                        (SiteProfileMatchKind::Mismatch, vec![format!("IP : {expected} → {host_ip}")])
                    }
                    _ => (SiteProfileMatchKind::Matched, Vec::new()),
                };
                entries.push(SiteProfileDiffEntry {
                    id,
                    kind,
                    entry: Some(entry.clone()),
                    host: Some((*host).clone()),
                    changes,
                });
                continue;
            }

            // Matching IP seulement pour une entrée SANS MAC : une MAC attendue introuvable
            // reste « manquante » même si son ancienne IP est occupée par un autre appareil.
            let by_ip = if mac.is_none() {
                expected_ip.and_then(|ip| ip.parse::<Ipv4Addr>().ok()).and_then(|ip| hosts_by_ip.get(&ip))
            } else {
                None
            };
            if let Some(host) = by_ip {
                claimed.insert(host.ip);
                entries.push(SiteProfileDiffEntry {
                    id,
                    kind: SiteProfileMatchKind::Matched,
                    entry: Some(entry.clone()),
                    host: Some((*host).clone()),
                    changes: Vec::new(),
                });
                continue;
            }

            entries.push(SiteProfileDiffEntry {
                id,
                kind: SiteProfileMatchKind::Missing,
                entry: Some(entry.clone()),
                host: None,
                changes: Vec::new(),
            });
        }

        for host in hosts {
            if claimed.insert(host.ip) {
                entries.push(SiteProfileDiffEntry {
                    id: format!("host:{}", host.ip),
                    kind: SiteProfileMatchKind::Unexpected,
                    entry: None,
                    host: Some(host.clone()),
                    changes: Vec::new(),
                });
            }
        }
        Self { profile: profile.clone(), entries }
    }

    pub fn of_kind(&self, kind: SiteProfileMatchKind) -> Vec<&SiteProfileDiffEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::HostStatus;
    use SiteProfileMatchKind as K;

    fn host(ip: &str, mac: Option<&str>) -> Host {
        let mut h = Host::new(ip.parse().unwrap());
        h.mac = mac.map(str::to_owned);
        h.status = HostStatus::Up;
        h
    }

    fn profile(entry: SiteProfileEntry) -> SiteProfile {
        SiteProfile::new("Site", vec![entry])
    }

    #[test]
    fn matched_by_mac_with_same_ip() {
        let p = profile(SiteProfileEntry::new("Test camera", Some("192.0.2.10"), Some("02:00:00:00:00:01")));
        let d = SiteProfileDiff::compute(&p, &[host("192.0.2.10", Some("02:00:00:00:00:01"))]);
        assert_eq!(d.of_kind(K::Matched).len(), 1);
        assert!(
            d.of_kind(K::Missing).is_empty()
                && d.of_kind(K::Mismatch).is_empty()
                && d.of_kind(K::Unexpected).is_empty()
        );
    }

    #[test]
    fn mismatch_when_mac_matches_but_ip_differs() {
        let p = profile(SiteProfileEntry::new("Test camera", Some("192.0.2.10"), Some("02:00:00:00:00:01")));
        let d = SiteProfileDiff::compute(&p, &[host("192.0.2.17", Some("02:00:00:00:00:01"))]);
        let mismatches = d.of_kind(K::Mismatch);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(mismatches[0].changes, ["IP : 192.0.2.10 → 192.0.2.17"]);
        assert!(d.of_kind(K::Missing).is_empty() && d.of_kind(K::Unexpected).is_empty());
    }

    #[test]
    fn mac_matching_is_case_insensitive() {
        let p = profile(SiteProfileEntry::new("Test camera", Some("192.0.2.10"), Some("02:00:00:00:00:01")));
        let d = SiteProfileDiff::compute(&p, &[host("192.0.2.17", Some("02:00:00:00:00:01"))]);
        assert_eq!(d.of_kind(K::Mismatch).len(), 1);
    }

    #[test]
    fn ip_only_entries() {
        let p = profile(SiteProfileEntry::new("Test printer", Some("192.0.2.20"), None));
        assert_eq!(SiteProfileDiff::compute(&p, &[host("192.0.2.20", None)]).of_kind(K::Matched).len(), 1);
        assert_eq!(SiteProfileDiff::compute(&p, &[]).of_kind(K::Missing).len(), 1);
        // MAC vide = pas de MAC.
        let p = profile(SiteProfileEntry::new("Test printer", Some("192.0.2.20"), Some("  ")));
        assert_eq!(SiteProfileDiff::compute(&p, &[host("192.0.2.20", None)]).of_kind(K::Matched).len(), 1);
    }

    #[test]
    fn missing_mac_even_if_old_ip_occupied() {
        let p = profile(SiteProfileEntry::new("Test camera", Some("192.0.2.10"), Some("02:00:00:00:00:01")));
        let d = SiteProfileDiff::compute(&p, &[host("192.0.2.10", Some("02:00:00:00:00:02"))]);
        assert_eq!(d.of_kind(K::Missing).len(), 1);
        let unexpected = d.of_kind(K::Unexpected);
        assert_eq!(unexpected.len(), 1);
        assert_eq!(unexpected[0].host.as_ref().unwrap().ip.to_string(), "192.0.2.10");
    }

    #[test]
    fn unexpected_unclaimed_host() {
        let d = SiteProfileDiff::compute(&SiteProfile::new("Site", vec![]), &[host("192.0.2.99", None)]);
        assert_eq!(d.of_kind(K::Unexpected).len(), 1);
    }

    #[test]
    fn invalid_entry_ip_is_just_missing() {
        let p = profile(SiteProfileEntry::new("X", Some("pas une ip"), None));
        assert_eq!(SiteProfileDiff::compute(&p, &[host("198.51.100.1", None)]).of_kind(K::Missing).len(), 1);
    }
}
