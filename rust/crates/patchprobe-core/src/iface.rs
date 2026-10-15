//! Choix de l'interface « active » parmi les interfaces IPv4 de la machine — logique pure,
//! testable ; l'énumération elle-même vit dans `patchprobe-platform`.

use std::net::Ipv4Addr;

use crate::range::InterfaceInfo;

/// Préfixes de noms d'interfaces virtuelles (conteneurs, VPN, hyperviseurs) à éviter.
const VIRTUAL_PREFIXES: [&str; 16] = [
    "docker",
    "veth",
    "br-",
    "virbr",
    "vmnet",
    "vboxnet",
    "utun",
    "tun",
    "tap",
    "wg",
    "zt",
    "tailscale",
    "lxc",
    "lxd",
    "awdl",
    "llw",
];
const VIRTUAL_SUBSTRINGS: [&str; 5] = ["virtualbox", "vmware", "vethernet", "hyper-v", "loopback"];
/// Noms courants des interfaces physiques, par ordre de préférence.
const PREFERRED_NAMES: [&str; 10] = ["en0", "en1", "eth0", "wlan0", "wlp", "enp", "eno", "ethernet", "wi-fi", "wlan"];

pub fn is_virtual_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    VIRTUAL_PREFIXES.iter().any(|p| lower.starts_with(p)) || VIRTUAL_SUBSTRINGS.iter().any(|s| lower.contains(s))
}

fn is_usable(info: &InterfaceInfo) -> bool {
    !info.ip.is_loopback() && !info.ip.is_link_local() && !info.ip.is_unspecified() && info.prefix_len > 0
}

/// Interface active : celle dont le sous-réseau contient la passerelle ; sinon une interface
/// physique (nom préféré, adresse privée) ; sinon la première utilisable.
pub fn choose_active_interface(interfaces: &[InterfaceInfo], gateway: Option<Ipv4Addr>) -> Option<InterfaceInfo> {
    let usable: Vec<&InterfaceInfo> = interfaces.iter().filter(|i| is_usable(i)).collect();
    if let Some(gw) = gateway {
        let mut matching: Vec<&&InterfaceInfo> = usable.iter().filter(|i| i.contains(gw)).collect();
        matching.sort_by_key(|i| is_virtual_name(&i.name));
        if let Some(found) = matching.first() {
            return Some((**found).clone());
        }
    }
    let rank = |info: &InterfaceInfo| {
        let lower = info.name.to_lowercase();
        let name_rank = PREFERRED_NAMES.iter().position(|p| lower.starts_with(p)).unwrap_or(PREFERRED_NAMES.len());
        (is_virtual_name(&info.name), !info.ip.is_private(), name_rank)
    };
    usable.into_iter().min_by_key(|i| rank(i)).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ip: [u8; 4], mask: [u8; 4]) -> InterfaceInfo {
        InterfaceInfo::new(name, Ipv4Addr::from(ip), Ipv4Addr::from(mask))
    }

    #[test]
    fn prefers_interface_on_gateway_subnet() {
        let list = [
            iface("docker0", [198, 51, 100, 1], [255, 255, 0, 0]),
            iface("utun3", [203, 0, 113, 2], [255, 255, 255, 0]),
            iface("en0", [192, 0, 2, 42], [255, 255, 255, 0]),
        ];
        assert_eq!(choose_active_interface(&list, Some(Ipv4Addr::new(192, 0, 2, 1))).unwrap().name, "en0");
        // Sans passerelle connue : l'interface physique au nom préféré.
        assert_eq!(choose_active_interface(&list, None).unwrap().name, "en0");
    }

    #[test]
    fn skips_loopback_and_link_local() {
        let list = [
            iface("lo", [127, 0, 0, 1], [255, 0, 0, 0]),
            iface("Ethernet 2", [169, 254, 3, 4], [255, 255, 0, 0]),
            iface("Wi-Fi", [198, 51, 100, 12], [255, 255, 255, 0]),
            iface("vEthernet (WSL)", [203, 0, 113, 1], [255, 255, 240, 0]),
        ];
        assert_eq!(choose_active_interface(&list, None).unwrap().name, "Wi-Fi");
        assert!(choose_active_interface(&list[..2], None).is_none());
    }

    #[test]
    fn virtual_names() {
        for name in [
            "docker0",
            "veth12ab",
            "br-1234",
            "utun2",
            "VirtualBox Host-Only Network",
            "vEthernet (Default Switch)",
            "tailscale0",
        ] {
            assert!(is_virtual_name(name), "{name}");
        }
        for name in ["en0", "eth0", "wlp3s0", "Wi-Fi", "Ethernet"] {
            assert!(!is_virtual_name(name), "{name}");
        }
    }
}
