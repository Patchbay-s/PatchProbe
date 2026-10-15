//! Base OUI IEEE (MA-L) — port de `OUIVendorDatabase.swift`.
//!
//! Le registre IEEE est embarqué dans le binaire et décodé paresseusement au premier lookup.

use std::collections::HashMap;
use std::sync::LazyLock;

static OUI_JSON: &str = include_str!("../resources/OUIVendors.json");

static DATABASE: LazyLock<HashMap<u32, Box<str>>> = LazyLock::new(|| {
    let raw: HashMap<String, String> = serde_json::from_str(OUI_JSON).unwrap_or_default();
    raw.into_iter().filter_map(|(key, vendor)| oui_key(&key).map(|k| (k, vendor.into_boxed_str()))).collect()
});

/// Nombre d'entrées chargées (≈ 39 688 pour le registre complet).
pub fn len() -> usize {
    DATABASE.len()
}

/// Fabricant d'une MAC. Accepte `:` ou `-`, toute casse, les octets non complétés de zéros que
/// produit `arp -a` sous macOS (`0:50:56:a:0:2`), ainsi que les formes `aabbccddeeff` et
/// `aabb.ccdd.eeff`.
pub fn vendor(mac: &str) -> Option<&'static str> {
    let key = oui_key(mac)?;
    DATABASE.get(&key).map(AsRef::as_ref)
}

/// Les 24 premiers bits de la MAC, ou `None` si la saisie n'en est pas une.
pub fn oui_key(mac: &str) -> Option<u32> {
    let mac = mac.trim();
    let octets: Vec<u8> = if mac.contains([':', '-']) {
        mac.split([':', '-'])
            .take(3)
            .map(|part| if part.is_empty() || part.len() > 2 { None } else { u8::from_str_radix(part, 16).ok() })
            .collect::<Option<Vec<u8>>>()?
    } else {
        let hex: String = mac.chars().filter(|c| *c != '.').collect();
        if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        (0..3)
            .map(|i| hex.get(i * 2..i * 2 + 2).and_then(|byte| u8::from_str_radix(byte, 16).ok()))
            .collect::<Option<Vec<u8>>>()?
    };
    match octets.as_slice() {
        [a, b, c] => Some(u32::from(*a) << 16 | u32::from(*b) << 8 | u32::from(*c)),
        _ => None,
    }
}

/// Normalise une MAC en `aa:bb:cc:dd:ee:ff` (minuscules, octets complétés), ou `None`.
pub fn normalize_mac(mac: &str) -> Option<String> {
    let mac = mac.trim();
    let parts: Vec<&str> = if mac.contains([':', '-']) {
        mac.split([':', '-']).collect()
    } else {
        let hex: String = mac.chars().filter(|c| *c != '.').collect();
        if hex.len() != 12 {
            return None;
        }
        return normalize_mac(&(0..6).filter_map(|i| hex.get(i * 2..i * 2 + 2)).collect::<Vec<_>>().join(":"));
    };
    if parts.len() != 6 {
        return None;
    }
    let bytes = parts
        .iter()
        .map(|p| if p.is_empty() || p.len() > 2 { None } else { u8::from_str_radix(p, 16).ok() })
        .collect::<Option<Vec<u8>>>()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_real_vendors() {
        assert_eq!(vendor("00:50:56:00:00:01"), Some("VMware, Inc."));
        assert_eq!(vendor("00:00:0C:00:00:03"), Some("Cisco Systems, Inc"));
        assert_eq!(vendor("00:1B:21:00:00:04"), Some("Intel Corporate"));
        assert_eq!(vendor("00:15:5D:00:00:05"), Some("Microsoft Corporation"));
    }

    #[test]
    fn resolves_non_zero_padded_arp_output() {
        assert_eq!(vendor("0:50:56:a:0:2"), Some("VMware, Inc."));
        assert_eq!(vendor("0:1b:21:0:0:4"), Some("Intel Corporate"));
    }

    #[test]
    fn case_and_separator_insensitive() {
        assert_eq!(vendor("00:50:56:00:00:01"), vendor("00-50-56-00-00-01"));
        assert_eq!(vendor("005056000001"), Some("VMware, Inc."));
        assert_eq!(vendor("0050.5600.0001"), Some("VMware, Inc."));
    }

    #[test]
    fn rejects_randomized_and_malformed() {
        assert_eq!(vendor("02:00:00:00:00:06"), None);
        assert_eq!(vendor(""), None);
        assert_eq!(vendor("zz:zz:zz"), None);
        assert_eq!(vendor("38:07"), None);
        assert_eq!(vendor("380:7:16:00:00:00"), None);
        assert_eq!(vendor("(incomplete)"), None);
    }

    #[test]
    fn substantial_coverage() {
        assert!(len() > 30_000, "base OUI trop petite : {}", len());
        let found = ["00:50:56", "00:00:0C", "00:1B:21", "00:15:5D", "00:1A:2B", "3C:22:FB", "F4:F5:D8"]
            .iter()
            .filter(|oui| vendor(&format!("{oui}:00:00:00")).is_some())
            .count();
        assert!(found >= 5);
    }

    #[test]
    fn normalizes_macs() {
        assert_eq!(normalize_mac("0:50:56:A:0:2").as_deref(), Some("00:50:56:0a:00:02"));
        assert_eq!(normalize_mac("02-00-00-00-00-01").as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(normalize_mac("020000000001").as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee:gg"), None);
    }
}
