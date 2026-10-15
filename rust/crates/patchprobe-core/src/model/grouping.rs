//! Groupement de la table (sous-réseau / fabricant / statut) — port de `HostGrouping.swift`.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::host::{natural_cmp, Host};

pub const UNKNOWN_VENDOR: &str = "Fabricant inconnu";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum GroupingOption {
    #[default]
    None,
    Subnet,
    Vendor,
    Status,
}

impl GroupingOption {
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "Aucun",
            Self::Subnet => "Sous-réseau",
            Self::Vendor => "Fabricant",
            Self::Status => "Statut",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostGroup<'a> {
    pub key: String,
    pub hosts: Vec<&'a Host>,
}

/// Groupe les hôtes et ordonne les groupes : sous-réseau par IP, fabricant alphabétique avec
/// « Fabricant inconnu » en dernier, statut par vivacité (actifs d'abord). L'ordre des hôtes
/// dans un groupe est conservé.
pub fn group_hosts(hosts: &[Host], option: GroupingOption) -> Vec<HostGroup<'_>> {
    if option == GroupingOption::None {
        return vec![HostGroup { key: String::new(), hosts: hosts.iter().collect() }];
    }
    let key_of = |host: &Host| -> String {
        match option {
            GroupingOption::Subnet => host.subnet_key(),
            GroupingOption::Vendor => host.vendor.clone().unwrap_or_else(|| UNKNOWN_VENDOR.to_owned()),
            GroupingOption::Status | GroupingOption::None => host.status_label().to_owned(),
        }
    };
    let mut order: Vec<String> = Vec::new();
    let mut buckets: HashMap<String, Vec<&Host>> = HashMap::new();
    for host in hosts {
        let key = key_of(host);
        buckets
            .entry(key.clone())
            .or_insert_with(|| {
                order.push(key);
                Vec::new()
            })
            .push(host);
    }
    let mut groups: Vec<HostGroup<'_>> =
        order.into_iter().filter_map(|key| buckets.remove(&key).map(|hosts| HostGroup { key, hosts })).collect();
    match option {
        GroupingOption::Subnet => {
            groups.sort_by_key(|g| g.hosts.iter().map(|h| h.ip).min());
        }
        GroupingOption::Vendor => groups.sort_by(|a, b| match (a.key == UNKNOWN_VENDOR, b.key == UNKNOWN_VENDOR) {
            (true, false) => std::cmp::Ordering::Greater,
            (false, true) => std::cmp::Ordering::Less,
            _ => natural_cmp(&a.key, &b.key),
        }),
        GroupingOption::Status => {
            groups.sort_by_key(|g| g.hosts.first().map_or(u8::MAX, |h| h.status.sort_key()));
        }
        GroupingOption::None => {}
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::host::HostStatus;

    fn make(ip: &str, vendor: Option<&str>, status: HostStatus) -> Host {
        let mut h = Host::new(ip.parse().unwrap());
        h.vendor = vendor.map(str::to_owned);
        h.status = status;
        h
    }

    fn keys(groups: &[HostGroup<'_>]) -> Vec<String> {
        groups.iter().map(|g| g.key.clone()).collect()
    }

    #[test]
    fn none_returns_single_group() {
        let hosts = [make("192.0.2.1", None, HostStatus::Up), make("192.0.2.2", None, HostStatus::Up)];
        let groups = group_hosts(&hosts, GroupingOption::None);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].hosts.len(), 2);
    }

    #[test]
    fn groups_by_subnet() {
        let hosts = [
            make("192.0.2.5", None, HostStatus::Up),
            make("192.0.2.10", None, HostStatus::Up),
            make("198.51.100.5", None, HostStatus::Up),
        ];
        let groups = group_hosts(&hosts, GroupingOption::Subnet);
        assert_eq!(keys(&groups), ["192.0.2.0/24", "198.51.100.0/24"]);
        assert_eq!(groups[0].hosts.len(), 2);
    }

    #[test]
    fn groups_by_vendor_unknown_last() {
        let hosts = [
            make("192.0.2.1", Some("Zyxel"), HostStatus::Up),
            make("192.0.2.2", None, HostStatus::Up),
            make("192.0.2.3", Some("Apple, Inc."), HostStatus::Up),
        ];
        let groups = group_hosts(&hosts, GroupingOption::Vendor);
        assert_eq!(keys(&groups), ["Apple, Inc.", "Zyxel", "Fabricant inconnu"]);
    }

    #[test]
    fn groups_by_status_up_first() {
        let hosts = [
            make("192.0.2.1", None, HostStatus::Down),
            make("192.0.2.2", None, HostStatus::Up),
            make("192.0.2.3", None, HostStatus::Unknown),
        ];
        assert_eq!(keys(&group_hosts(&hosts, GroupingOption::Status)), ["Actif", "Inconnu", "Inactif"]);
    }

    #[test]
    fn empty_input_produces_no_groups_when_grouped() {
        for option in [GroupingOption::Subnet, GroupingOption::Vendor, GroupingOption::Status] {
            assert!(group_hosts(&[], option).is_empty());
        }
    }
}
