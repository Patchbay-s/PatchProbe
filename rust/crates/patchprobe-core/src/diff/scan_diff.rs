//! Diff entre deux scans sauvegardés — port de `ScanDiff.swift`.

use std::collections::{BTreeSet, HashMap};
use std::net::Ipv4Addr;

use serde::Serialize;

use crate::model::snapshot::{HostSnapshot, ScanSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum HostChangeKind {
    New,
    Gone,
    Changed,
    Unchanged,
}

impl HostChangeKind {
    fn rank(self) -> u8 {
        match self {
            Self::New => 0,
            Self::Gone => 1,
            Self::Changed => 2,
            Self::Unchanged => 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDiffEntry {
    pub ip: Ipv4Addr,
    pub kind: HostChangeKind,
    pub before: Option<HostSnapshot>,
    pub after: Option<HostSnapshot>,
    /// Lignes lisibles, ex. « nom : nas → nas.example.invalid », « ports : +443 -8080 ».
    pub changes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanDiff {
    pub older: ScanSnapshot,
    pub newer: ScanSnapshot,
    pub entries: Vec<HostDiffEntry>,
}

impl ScanDiff {
    /// Ordonne les deux snapshots par date quel que soit l'ordre d'appel.
    pub fn compute(a: &ScanSnapshot, b: &ScanSnapshot) -> Self {
        let (older, newer) = if a.date <= b.date { (a, b) } else { (b, a) };
        let older_by_ip = first_by_ip(&older.hosts);
        let newer_by_ip = first_by_ip(&newer.hosts);
        let all_ips: BTreeSet<Ipv4Addr> = older_by_ip.keys().chain(newer_by_ip.keys()).copied().collect();

        let mut entries: Vec<HostDiffEntry> = all_ips
            .into_iter()
            .filter_map(|ip| {
                let before = older_by_ip.get(&ip).copied();
                let after = newer_by_ip.get(&ip).copied();
                let (kind, changes) = match (before, after) {
                    (None, Some(_)) => (HostChangeKind::New, Vec::new()),
                    (Some(_), None) => (HostChangeKind::Gone, Vec::new()),
                    (Some(b), Some(a)) => {
                        let changes = field_changes(b, a);
                        let kind = if changes.is_empty() { HostChangeKind::Unchanged } else { HostChangeKind::Changed };
                        (kind, changes)
                    }
                    (None, None) => return None,
                };
                Some(HostDiffEntry { ip, kind, before: before.cloned(), after: after.cloned(), changes })
            })
            .collect();
        entries.sort_by_key(|e| (e.kind.rank(), e.ip));
        Self { older: older.clone(), newer: newer.clone(), entries }
    }

    pub fn of_kind(&self, kind: HostChangeKind) -> impl Iterator<Item = &HostDiffEntry> {
        self.entries.iter().filter(move |e| e.kind == kind)
    }
}

/// Premier hôte gagnant en cas d'IP dupliquée (fichier sur disque corrompu mais décodable).
fn first_by_ip(hosts: &[HostSnapshot]) -> HashMap<Ipv4Addr, &HostSnapshot> {
    let mut map = HashMap::new();
    for host in hosts {
        map.entry(host.ip).or_insert(host);
    }
    map
}

fn show(value: Option<&String>) -> &str {
    value.map_or("—", String::as_str)
}

fn field_changes(before: &HostSnapshot, after: &HostSnapshot) -> Vec<String> {
    let mut changes = Vec::new();
    if before.hostname != after.hostname {
        changes.push(format!("nom : {} → {}", show(before.hostname.as_ref()), show(after.hostname.as_ref())));
    }
    if before.mac != after.mac {
        changes.push(format!("MAC : {} → {}", show(before.mac.as_ref()), show(after.mac.as_ref())));
    }
    if before.vendor != after.vendor {
        changes.push(format!("fabricant : {} → {}", show(before.vendor.as_ref()), show(after.vendor.as_ref())));
    }
    let before_ports: BTreeSet<u16> = before.open_ports.iter().copied().collect();
    let after_ports: BTreeSet<u16> = after.open_ports.iter().copied().collect();
    if before_ports != after_ports {
        let join = |ports: Vec<&u16>| ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
        let added: Vec<&u16> = after_ports.difference(&before_ports).collect();
        let removed: Vec<&u16> = before_ports.difference(&after_ports).collect();
        let mut parts = Vec::new();
        if !added.is_empty() {
            parts.push(format!("+{}", join(added)));
        }
        if !removed.is_empty() {
            parts.push(format!("-{}", join(removed)));
        }
        changes.push(format!("ports : {}", parts.join(" ")));
    }
    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    fn snap(secs: i64, hosts: Vec<HostSnapshot>) -> ScanSnapshot {
        ScanSnapshot {
            id: Uuid::new_v4(),
            date: Utc.timestamp_opt(secs, 0).unwrap(),
            range_input: "192.0.2.1-255".into(),
            hosts,
        }
    }

    fn hs(ip: &str, hostname: Option<&str>, ports: &[u16], mac: Option<&str>) -> HostSnapshot {
        HostSnapshot {
            ip: ip.parse().unwrap(),
            hostname: hostname.map(str::to_owned),
            latency_ms: None,
            open_ports: ports.to_vec(),
            mac: mac.map(str::to_owned),
            vendor: None,
            probable_os: None,
        }
    }

    fn ips<'a>(it: impl Iterator<Item = &'a HostDiffEntry>) -> Vec<String> {
        it.map(|e| e.ip.to_string()).collect()
    }

    #[test]
    fn detects_new_and_gone() {
        let older = snap(0, vec![hs("192.0.2.1", Some("router"), &[80], Some("02:00:00:00:00:01"))]);
        let newer = snap(100, vec![hs("192.0.2.2", Some("nas"), &[445], None)]);
        let diff = ScanDiff::compute(&older, &newer);
        assert_eq!(ips(diff.of_kind(HostChangeKind::New)), ["192.0.2.2"]);
        assert_eq!(ips(diff.of_kind(HostChangeKind::Gone)), ["192.0.2.1"]);
        assert_eq!(diff.of_kind(HostChangeKind::Changed).count(), 0);
    }

    #[test]
    fn orders_by_date_regardless_of_arguments() {
        let (earlier, later) = (snap(0, vec![]), snap(100, vec![]));
        for diff in [ScanDiff::compute(&earlier, &later), ScanDiff::compute(&later, &earlier)] {
            assert_eq!(diff.older.date, earlier.date);
            assert_eq!(diff.newer.date, later.date);
        }
    }

    #[test]
    fn unchanged_hostname_and_port_changes() {
        let host = hs("192.0.2.1", Some("router"), &[80, 443], Some("02:00:00:00:00:01"));
        let diff = ScanDiff::compute(&snap(0, vec![host.clone()]), &snap(100, vec![host]));
        assert_eq!(ips(diff.of_kind(HostChangeKind::Unchanged)), ["192.0.2.1"]);

        let diff = ScanDiff::compute(
            &snap(0, vec![hs("192.0.2.5", Some("old-name"), &[22, 80], None)]),
            &snap(100, vec![hs("192.0.2.5", Some("new-name"), &[80, 443], None)]),
        );
        let changed: Vec<&HostDiffEntry> = diff.of_kind(HostChangeKind::Changed).collect();
        assert_eq!(changed.len(), 1);
        assert!(changed[0].changes.contains(&"nom : old-name → new-name".to_owned()));
        assert!(changed[0].changes.contains(&"ports : +443 -22".to_owned()));
    }

    #[test]
    fn entries_ordered_new_gone_changed_unchanged() {
        let older = snap(
            0,
            vec![
                hs("192.0.2.1", Some("gone-host"), &[], None),
                hs("192.0.2.2", Some("changed-host"), &[22], None),
                hs("192.0.2.3", Some("same-host"), &[], None),
            ],
        );
        let newer = snap(
            100,
            vec![
                hs("192.0.2.2", Some("changed-host"), &[23], None),
                hs("192.0.2.3", Some("same-host"), &[], None),
                hs("192.0.2.4", Some("new-host"), &[], None),
            ],
        );
        let diff = ScanDiff::compute(&older, &newer);
        let kinds: Vec<HostChangeKind> = diff.entries.iter().map(|e| e.kind).collect();
        assert_eq!(
            kinds,
            [HostChangeKind::New, HostChangeKind::Gone, HostChangeKind::Changed, HostChangeKind::Unchanged]
        );
    }

    #[test]
    fn duplicated_ips_do_not_panic() {
        let dup = hs("198.51.100.1", Some("a"), &[], None);
        let diff = ScanDiff::compute(&snap(0, vec![dup.clone(), dup.clone()]), &snap(1, vec![dup]));
        assert_eq!(diff.entries.len(), 1);
    }
}
