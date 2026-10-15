//! Corrections manuelles du fabricant, par MAC — port de `VendorOverrideStore.swift`.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use super::host::Host;
use crate::oui::normalize_mac;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct VendorOverrides {
    by_mac: BTreeMap<String, String>,
}

fn key(mac: &str) -> String {
    normalize_mac(mac).unwrap_or_else(|| mac.trim().to_lowercase())
}

impl VendorOverrides {
    pub fn get(&self, mac: Option<&str>) -> Option<&str> {
        mac.and_then(|m| self.by_mac.get(&key(m))).map(String::as_str)
    }

    pub fn has(&self, mac: Option<&str>) -> bool {
        self.get(mac).is_some()
    }

    /// Valeur vide ou blanche : supprime la correction.
    pub fn set(&mut self, mac: &str, vendor: &str) {
        let trimmed = vendor.trim();
        if trimmed.is_empty() {
            self.by_mac.remove(&key(mac));
        } else {
            self.by_mac.insert(key(mac), trimmed.chars().take(200).collect());
        }
    }

    pub fn apply(&self, host: &Host) -> Host {
        let mut host = host.clone();
        if let Some(custom) = self.get(host.mac.as_deref()) {
            host.vendor = Some(custom.to_owned());
            host.vendor_overridden = true;
            host.refresh_derived();
        }
        host
    }

    pub fn as_map(&self) -> HashMap<String, String> {
        self.by_mac.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: &str = "02:00:00:00:00:01";

    #[test]
    fn swift_vectors() {
        let mut o = VendorOverrides::default();
        o.set(MAC, "Test vendor");
        assert_eq!(o.get(Some(MAC)), Some("Test vendor"));
        assert_eq!(o.get(Some("02:00:00:00:00:02")), None);
        assert_eq!(o.get(None), None);
        o.set("02:00:00:00:00:03", "Test vendor");
        assert_eq!(o.get(Some("02:00:00:00:00:03")), Some("Test vendor"));
        assert_eq!(o.get(Some("02-00-00-00-00-03")), Some("Test vendor"));
        o.set(MAC, "");
        assert!(!o.has(Some(MAC)));
        o.set(MAC, "Custom Name");
        o.set(MAC, "   ");
        assert!(!o.has(Some(MAC)));
    }

    #[test]
    fn apply_replaces_vendor_only_with_override() {
        let mut o = VendorOverrides::default();
        o.set(MAC, "Custom Name");
        let mut host = Host::new("192.0.2.50".parse().unwrap());
        host.mac = Some(MAC.into());
        host.vendor = Some("Original OUI Vendor".into());
        let applied = o.apply(&host);
        assert_eq!(applied.vendor.as_deref(), Some("Custom Name"));
        assert!(applied.vendor_overridden);
        host.mac = Some("02:00:00:00:00:02".into());
        assert_eq!(o.apply(&host).vendor.as_deref(), Some("Original OUI Vendor"));
    }
}
