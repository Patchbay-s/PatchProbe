//! Parseurs de la table ARP / voisins : macOS `arp -an`, Linux `ip neigh` et `/proc/net/arp`,
//! Windows `arp -a` (toutes langues). Entrées incomplètes, échouées, broadcast et multicast
//! exclues ; MAC normalisées en `aa:bb:cc:dd:ee:ff`.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::oui::normalize_mac;

/// MAC utilisable : unicast, ni nulle ni broadcast.
fn usable_mac(raw: &str) -> Option<String> {
    let mac = normalize_mac(raw)?;
    let first = u8::from_str_radix(mac.get(0..2)?, 16).ok()?;
    let is_multicast = first & 0x01 != 0; // couvre aussi ff:ff:ff:ff:ff:ff
    (mac != "00:00:00:00:00:00" && !is_multicast).then_some(mac)
}

fn strip_parens(token: &str) -> &str {
    token.trim_start_matches('(').trim_end_matches(')')
}

/// macOS/BSD : `? (192.0.2.1) at 02:00:00:00:00:01 on en0 ifscope [ethernet]`.
pub fn parse_bsd_arp(output: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = HashMap::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = tokens.iter().position(|t| *t == "at") else { continue };
        let Some(ip) = tokens.iter().take(at).find_map(|t| strip_parens(t).parse::<Ipv4Addr>().ok()) else { continue };
        let Some(mac) = tokens.get(at + 1).and_then(|m| usable_mac(m)) else { continue };
        table.insert(ip, mac);
    }
    table
}

/// Linux : `192.0.2.1 dev wlan0 lladdr 02:00:00:00:00:01 REACHABLE`.
pub fn parse_ip_neigh(output: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = HashMap::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(ip) = tokens.first().and_then(|t| t.parse::<Ipv4Addr>().ok()) else { continue };
        let state = tokens.last().copied().unwrap_or_default();
        if matches!(state, "FAILED" | "INCOMPLETE" | "NONE") {
            continue;
        }
        let Some(mac) =
            tokens.iter().position(|t| *t == "lladdr").and_then(|i| tokens.get(i + 1)).and_then(|m| usable_mac(m))
        else {
            continue;
        };
        table.insert(ip, mac);
    }
    table
}

/// Linux : `/proc/net/arp` (drapeaux 0x0 = entrée incomplète).
pub fn parse_proc_net_arp(content: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = HashMap::new();
    for line in content.lines().skip(1) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (Some(ip), Some(flags), Some(mac)) = (tokens.first(), tokens.get(2), tokens.get(3)) else { continue };
        if *flags == "0x0" {
            continue;
        }
        if let (Ok(ip), Some(mac)) = (ip.parse::<Ipv4Addr>(), usable_mac(mac)) {
            table.insert(ip, mac);
        }
    }
    table
}

/// Windows : lignes `  192.0.2.1           02-00-00-00-00-01     dynamique`, quelle que soit la
/// langue des en-têtes.
pub fn parse_windows_arp(output: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = HashMap::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (Some(ip), Some(mac)) = (tokens.first(), tokens.get(1)) else { continue };
        if let (Ok(ip), Some(mac)) = (ip.parse::<Ipv4Addr>(), usable_mac(mac)) {
            table.insert(ip, mac);
        }
    }
    table
}

/// Essaie chaque format (utile pour une sortie d'origine inconnue).
pub fn parse_any(output: &str) -> HashMap<Ipv4Addr, String> {
    let mut table = parse_bsd_arp(output);
    if table.is_empty() {
        table = parse_ip_neigh(output);
    }
    if table.is_empty() {
        table = parse_windows_arp(output);
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn macos_arp_an() {
        let out = "? (192.0.2.1) at 02:00:00:00:00:01 on en0 ifscope [ethernet]\n\
                   ? (192.0.2.12) at (incomplete) on en0 ifscope [ethernet]\n\
                   device-2 (192.0.2.20) at 02:00:00:00:00:02 on en0 ifscope [ethernet]\n\
                   ? (192.0.2.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                   ? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]\n";
        let table = parse_bsd_arp(out);
        assert_eq!(table.len(), 2);
        assert_eq!(table[&ip("192.0.2.1")], "02:00:00:00:00:01");
        assert_eq!(table[&ip("192.0.2.20")], "02:00:00:00:00:02");
    }

    #[test]
    fn linux_ip_neigh() {
        let out = "192.0.2.1 dev wlan0 lladdr 02:00:00:00:00:01 REACHABLE\n\
                   192.0.2.5 dev wlan0  FAILED\n\
                   192.0.2.6 dev wlan0 lladdr 02:00:00:00:00:03 STALE\n\
                   192.0.2.7 dev wlan0  INCOMPLETE\n\
                   fe80::1 dev wlan0 lladdr 02:00:00:00:00:01 router STALE\n";
        let table = parse_ip_neigh(out);
        assert_eq!(table.len(), 2);
        assert_eq!(table[&ip("192.0.2.6")], "02:00:00:00:00:03");
    }

    #[test]
    fn linux_proc_net_arp() {
        let content = "IP address       HW type     Flags       HW address            Mask     Device\n\
                       192.0.2.1      0x1         0x2         02:00:00:00:00:01     *        wlan0\n\
                       192.0.2.9      0x1         0x0         00:00:00:00:00:00     *        wlan0\n";
        let table = parse_proc_net_arp(content);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&ip("192.0.2.1")], "02:00:00:00:00:01");
    }

    #[test]
    fn windows_arp_a_french_and_english() {
        let fr = "\r\nInterface : 192.0.2.10 --- 0xb\r\n  Adresse Internet      Adresse physique      Type\r\n  192.0.2.1           02-00-00-00-00-01     dynamique\r\n  192.0.2.255         ff-ff-ff-ff-ff-ff     statique\r\n  224.0.0.22            01-00-5e-00-00-16     statique\r\n";
        let en = "Interface: 198.51.100.5 --- 0x4\r\n  Internet Address      Physical Address      Type\r\n  198.51.100.1              02-00-00-00-00-04     dynamic\r\n";
        let table = parse_windows_arp(fr);
        assert_eq!(table.len(), 1);
        assert_eq!(table[&ip("192.0.2.1")], "02:00:00:00:00:01");
        assert_eq!(parse_windows_arp(en)[&ip("198.51.100.1")], "02:00:00:00:00:04");
        assert_eq!(parse_any(en).len(), 1);
    }
}
