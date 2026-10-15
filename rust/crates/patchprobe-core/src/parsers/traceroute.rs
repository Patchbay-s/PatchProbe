//! Parseur des sorties traceroute (macOS/BSD/Linux `-n`), `tracepath` (Linux) et `tracert -d`
//! (Windows, toutes langues) — port de `TracerouteService.parseOutput`, étendu.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TracerouteHop {
    pub hop: u32,
    /// `None` quand toutes les sondes de ce saut ont expiré (`*`).
    pub address: Option<Ipv4Addr>,
    pub rtt_ms: Option<f64>,
}

fn hop_number(token: &str) -> Option<u32> {
    token.trim_end_matches(':').trim_end_matches('?').trim_end_matches(':').parse().ok()
}

fn parse_ms_value(text: &str) -> Option<f64> {
    let text = text.trim_start_matches('<').replace(',', ".");
    text.parse::<f64>().ok().filter(|v| v.is_finite() && *v >= 0.0)
}

fn first_rtt(tokens: &[&str]) -> Option<f64> {
    for (index, token) in tokens.iter().enumerate() {
        let lower = token.to_ascii_lowercase();
        if lower == "ms" {
            if let Some(value) = index.checked_sub(1).and_then(|i| tokens.get(i)).and_then(|t| parse_ms_value(t)) {
                return Some(value);
            }
        } else if let Some(prefix) = lower.strip_suffix("ms") {
            if let Some(value) = parse_ms_value(prefix) {
                return Some(value);
            }
        }
    }
    None
}

fn address(tokens: &[&str]) -> Option<Ipv4Addr> {
    tokens.iter().find_map(|t| t.trim_matches(|c| matches!(c, '(' | ')' | '[' | ']')).parse().ok())
}

/// Sauts lus dans la sortie ; bannières et lignes inattendues ignorées sans erreur. Si un même
/// numéro de saut apparaît deux fois (tracepath), la ligne avec une adresse l'emporte.
pub fn parse_traceroute(output: &str) -> Vec<TracerouteHop> {
    let mut hops: Vec<TracerouteHop> = Vec::new();
    for line in output.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some((first, rest)) = tokens.split_first() else { continue };
        let Some(hop) = hop_number(first) else { continue };
        if rest.is_empty() || hop == 0 || hop > 255 {
            continue;
        }
        let parsed = TracerouteHop { hop, address: address(rest), rtt_ms: first_rtt(rest) };
        match hops.iter_mut().find(|h| h.hop == hop) {
            Some(existing) if existing.address.is_none() => *existing = parsed,
            Some(_) => {}
            None => hops.push(parsed),
        }
    }
    hops
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Option<Ipv4Addr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn swift_vectors() {
        let out = "traceroute to 203.0.113.8 (203.0.113.8), 30 hops max, 60 byte packets\n 1  192.0.2.1  1.234 ms\n 2  198.51.100.1  9.876 ms\n 3  203.0.113.8  15.432 ms\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0], TracerouteHop { hop: 1, address: ip("192.0.2.1"), rtt_ms: Some(1.234) });
        assert_eq!(hops[2].rtt_ms, Some(15.432));

        let hops = parse_traceroute(
            "traceroute to 203.0.113.8\n 1  192.0.2.1  1.234 ms\n 2  * * *\n 3  203.0.113.8  15.432 ms",
        );
        assert_eq!(hops.len(), 3);
        assert_eq!((hops[1].address, hops[1].rtt_ms), (None, None));

        assert_eq!(parse_traceroute("traceroute to 203.0.113.8\n 1  *").len(), 1);
        assert!(parse_traceroute("").is_empty());
        let hops = parse_traceroute("traceroute to x\ngarbage line with no hop number\n 1  192.0.2.1  1.234 ms");
        assert_eq!(hops.len(), 1);
    }

    #[test]
    fn macos_style_with_star_first_probe() {
        let out = "traceroute to 198.51.100.10 (198.51.100.10), 64 hops max, 52 byte packets\n 1  192.0.2.254  2.104 ms\n 2  * 203.0.113.2  12.402 ms\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops[1].address, ip("203.0.113.2"));
        assert_eq!(hops[1].rtt_ms, Some(12.402));
    }

    #[test]
    fn windows_tracert_french() {
        let out = "\r\nDétermination de l’itinéraire vers 203.0.113.8 avec un maximum de 30 sauts.\r\n\r\n  1    <1 ms    <1 ms    <1 ms  192.0.2.254\r\n  2     *        *        *     Délai d’attente de la demande dépassé.\r\n  3    12 ms    11 ms    13 ms  203.0.113.8\r\n\r\nItinéraire déterminé.\r\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0], TracerouteHop { hop: 1, address: ip("192.0.2.254"), rtt_ms: Some(1.0) });
        assert_eq!((hops[1].address, hops[1].rtt_ms), (None, None));
        assert_eq!(hops[2], TracerouteHop { hop: 3, address: ip("203.0.113.8"), rtt_ms: Some(12.0) });
    }

    #[test]
    fn windows_tracert_english() {
        let out = "Tracing route to 198.51.100.10 over a maximum of 30 hops\n\n  1     1 ms     1 ms     1 ms  198.51.100.1\n  2     *        *        *     Request timed out.\n\nTrace complete.\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops.len(), 2);
        assert_eq!(hops[0].address, ip("198.51.100.1"));
    }

    #[test]
    fn linux_tracepath() {
        let out = " 1?: [LOCALHOST]                      pmtu 1500\n 1:  192.0.2.1                                           0.512ms \n 1:  192.0.2.1                                           0.401ms \n 2:  203.0.113.1                                             8,750ms asymm  3\n 3:  no reply\n     Resume: pmtu 1500\n";
        let hops = parse_traceroute(out);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0], TracerouteHop { hop: 1, address: ip("192.0.2.1"), rtt_ms: Some(0.512) });
        assert_eq!(hops[1].rtt_ms, Some(8.75));
        assert_eq!(hops[2].address, None);
    }
}
