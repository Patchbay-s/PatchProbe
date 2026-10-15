//! Passerelle par défaut : macOS `route -n get default`, Linux `/proc/net/route` et
//! `ip route show default`, Windows `route print -4 0.0.0.0`.

use std::net::Ipv4Addr;

/// macOS/BSD : ligne `gateway: 192.0.2.1`.
pub fn parse_bsd_route_get(output: &str) -> Option<Ipv4Addr> {
    output.lines().find_map(|line| {
        let value = line.trim().strip_prefix("gateway:")?.trim();
        value.parse().ok()
    })
}

/// Linux : `default via 192.0.2.1 dev wlan0 proto dhcp metric 600` (métrique la plus basse,
/// et interface préférée si fournie).
pub fn parse_ip_route_default(output: &str, preferred_iface: Option<&str>) -> Option<Ipv4Addr> {
    let mut best: Option<(bool, u32, Ipv4Addr)> = None;
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.first() != Some(&"default") {
            continue;
        }
        let value_after = |key: &str| tokens.iter().position(|t| *t == key).and_then(|i| tokens.get(i + 1)).copied();
        let Some(gateway) = value_after("via").and_then(|g| g.parse::<Ipv4Addr>().ok()) else { continue };
        let metric = value_after("metric").and_then(|m| m.parse().ok()).unwrap_or(0);
        let not_preferred = preferred_iface.is_some_and(|p| value_after("dev") != Some(p));
        let candidate = (not_preferred, metric, gateway);
        if best.is_none_or(|b| (candidate.0, candidate.1) < (b.0, b.1)) {
            best = Some(candidate);
        }
    }
    best.map(|(_, _, gw)| gw)
}

fn hex_le_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let value = u32::from_str_radix(hex, 16).ok()?;
    Some(Ipv4Addr::from(value.swap_bytes()))
}

/// Linux : `/proc/net/route` (adresses en hexadécimal little-endian).
pub fn parse_proc_net_route(content: &str, preferred_iface: Option<&str>) -> Option<Ipv4Addr> {
    let mut best: Option<(bool, u32, Ipv4Addr)> = None;
    for line in content.lines().skip(1) {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (Some(iface), Some(dest), Some(gw), Some(metric)) =
            (tokens.first(), tokens.get(1), tokens.get(2), tokens.get(6))
        else {
            continue;
        };
        if *dest != "00000000" {
            continue;
        }
        let Some(gateway) = hex_le_ipv4(gw).filter(|g| !g.is_unspecified()) else { continue };
        let metric = metric.parse().unwrap_or(u32::MAX);
        let not_preferred = preferred_iface.is_some_and(|p| p != *iface);
        if best.is_none_or(|b| (not_preferred, metric) < (b.0, b.1)) {
            best = Some((not_preferred, metric, gateway));
        }
    }
    best.map(|(_, _, gw)| gw)
}

/// Windows : lignes `0.0.0.0  0.0.0.0  <passerelle>  <interface>  <métrique>` ; métrique la plus
/// basse, interface préférée (par son IP) si fournie. « On-link »/« Sur la liaison » ignorés.
pub fn parse_windows_route_print(output: &str, preferred_iface_ip: Option<Ipv4Addr>) -> Option<Ipv4Addr> {
    let mut best: Option<(bool, u32, Ipv4Addr)> = None;
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let [dest, mask, gateway, iface, metric, ..] = tokens.as_slice() else { continue };
        if *dest != "0.0.0.0" || *mask != "0.0.0.0" {
            continue;
        }
        let Ok(gateway) = gateway.parse::<Ipv4Addr>() else { continue };
        let metric = metric.parse().unwrap_or(u32::MAX);
        let not_preferred = preferred_iface_ip.is_some_and(|p| iface.parse::<Ipv4Addr>().ok() != Some(p));
        if best.is_none_or(|b| (not_preferred, metric) < (b.0, b.1)) {
            best = Some((not_preferred, metric, gateway));
        }
    }
    best.map(|(_, _, gw)| gw)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn macos_route_get() {
        let out = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.0.2.254\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_bsd_route_get(out), Some(ip("192.0.2.254")));
        assert_eq!(parse_bsd_route_get("route: writing to routing socket: not in table\n"), None);
    }

    #[test]
    fn linux_ip_route() {
        let out = "default via 203.0.113.1 dev tun0 proto static metric 50\ndefault via 192.0.2.1 dev wlan0 proto dhcp src 192.0.2.42 metric 600\n";
        assert_eq!(parse_ip_route_default(out, None), Some(ip("203.0.113.1")));
        assert_eq!(parse_ip_route_default(out, Some("wlan0")), Some(ip("192.0.2.1")));
        assert_eq!(parse_ip_route_default("", None), None);
    }

    #[test]
    fn linux_proc_route() {
        let content = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                       wlan0\t00000000\t010200C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
                       wlan0\t000200C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(content, None), Some(ip("192.0.2.1")));
    }

    #[test]
    fn windows_route_print() {
        let fr = "===========================================================================\r\nItinéraires actifs :\r\nDestination réseau    Masque réseau  Adr. passerelle   Adr. interface Métrique\r\n          0.0.0.0          0.0.0.0      192.0.2.1     192.0.2.10     25\r\n          0.0.0.0          0.0.0.0        198.51.100.1       198.51.100.5       35\r\n        127.0.0.0        255.0.0.0   Sur la liaison         127.0.0.1    331\r\n";
        assert_eq!(parse_windows_route_print(fr, None), Some(ip("192.0.2.1")));
        assert_eq!(parse_windows_route_print(fr, Some(ip("198.51.100.5"))), Some(ip("198.51.100.1")));
        let en = "          0.0.0.0          0.0.0.0         On-link      203.0.113.2    5\r\n          0.0.0.0          0.0.0.0     198.51.100.1    198.51.100.9     50\r\n";
        assert_eq!(parse_windows_route_print(en, None), Some(ip("198.51.100.1")));
    }
}
