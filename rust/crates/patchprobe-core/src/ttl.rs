//! Heuristiques sur le TTL d'une réponse ping — port de `PingResult.isLikelyRouted/probableOS`.
//!
//! Plafonds courants : 64 (Linux/macOS), 128 (Windows), 255 (équipement réseau). Le plafond
//! retenu est le premier ≥ TTL observé.

pub const OS_LINUX_MACOS: &str = "Linux/macOS";
pub const OS_WINDOWS: &str = "Windows";
pub const OS_NETWORK_GEAR: &str = "Équipement réseau";

const CEILINGS: [(u8, &str); 3] = [(64, OS_LINUX_MACOS), (128, OS_WINDOWS), (255, OS_NETWORK_GEAR)];

fn ceiling(ttl: u8) -> Option<(u8, &'static str)> {
    CEILINGS.into_iter().find(|(ceiling, _)| *ceiling >= ttl)
}

/// Famille d'OS probable (indicatif : NAT/pare-feu peuvent réécrire le TTL).
pub fn probable_os(ttl: Option<u8>) -> Option<&'static str> {
    ttl.and_then(ceiling).map(|(_, label)| label)
}

/// Vrai si la réponse a traversé au moins un routeur (VM/conteneur derrière un routeur
/// interne…) : la vraie MAC ne peut alors pas être découverte par ARP. Sans TTL : faux.
pub fn is_likely_routed(ttl: Option<u8>) -> bool {
    match ttl.and_then(|t| ceiling(t).map(|(c, _)| (c, t))) {
        Some((ceiling, ttl)) => ceiling > ttl,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_neighbors_are_not_routed() {
        for ttl in [64, 128, 255] {
            assert!(!is_likely_routed(Some(ttl)));
        }
    }

    #[test]
    fn one_hop_is_routed() {
        assert!(is_likely_routed(Some(63)));
        assert!(is_likely_routed(Some(127)));
        assert!(!is_likely_routed(None));
    }

    #[test]
    fn probable_os_from_nearest_ceiling() {
        assert_eq!(probable_os(Some(64)), Some("Linux/macOS"));
        assert_eq!(probable_os(Some(63)), Some("Linux/macOS"));
        assert_eq!(probable_os(Some(128)), Some("Windows"));
        assert_eq!(probable_os(Some(120)), Some("Windows"));
        assert_eq!(probable_os(Some(255)), Some("Équipement réseau"));
        assert_eq!(probable_os(Some(250)), Some("Équipement réseau"));
        assert_eq!(probable_os(None), None);
    }
}
