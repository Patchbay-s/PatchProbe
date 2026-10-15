//! Parseur tolérant de la sortie d'un ping unique (macOS, Linux, Windows, toutes langues).
//!
//! Une réponse est reconnue à son TTL (`ttl=64`, `TTL=128`, `ttl:64`) : c'est le seul marqueur
//! commun à toutes les implémentations et traductions. Les lignes « TTL expiré » ou « Impossible
//! de joindre l'hôte » n'en ont pas et ne comptent donc pas comme réponses.

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PingParse {
    pub ttl: Option<u8>,
    pub latency_ms: Option<f64>,
}

impl PingParse {
    pub fn replied(&self) -> bool {
        self.ttl.is_some()
    }
}

/// Nombre (chiffres, `.` ou `,` décimal) au début de `text`.
fn leading_number(text: &str) -> Option<(f64, &str)> {
    let end = text.find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ',')).unwrap_or(text.len());
    let (number, rest) = text.split_at(end);
    let value = number.replace(',', ".").parse::<f64>().ok()?;
    Some((value, rest))
}

fn ttl_in(line: &str) -> Option<u8> {
    let lower = line.to_ascii_lowercase();
    let mut search = 0;
    while let Some(pos) = lower.get(search..).and_then(|s| s.find("ttl")) {
        let after = lower.get(search + pos + 3..).unwrap_or_default().trim_start();
        if let Some(value) = after.strip_prefix(['=', ':']) {
            let digits: String = value.trim_start().chars().take_while(char::is_ascii_digit).collect();
            if let Some(ttl) = digits.parse::<u16>().ok().and_then(|v| u8::try_from(v).ok()) {
                return Some(ttl);
            }
        }
        search += pos + 3;
    }
    None
}

/// Premier `=N ms` ou `<N ms` de la ligne (`time=1.2 ms`, `temps<1ms`, `Zeit=3ms`).
fn latency_in(line: &str) -> Option<f64> {
    for (index, c) in line.char_indices() {
        if c != '=' && c != '<' {
            continue;
        }
        let Some((value, rest)) = line.get(index + 1..).map(str::trim_start).and_then(leading_number) else { continue };
        if rest.trim_start().to_ascii_lowercase().starts_with("ms") {
            // « <1 ms » (Windows) : borne supérieure.
            return Some(value).filter(|v| v.is_finite() && *v >= 0.0);
        }
    }
    None
}

pub fn parse_ping(output: &str) -> PingParse {
    for line in output.lines() {
        if let Some(ttl) = ttl_in(line) {
            return PingParse { ttl: Some(ttl), latency_ms: latency_in(line) };
        }
    }
    PingParse { ttl: None, latency_ms: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MACOS: &str = "PING 192.0.2.1 (192.0.2.1): 56 data bytes\n64 bytes from 192.0.2.1: icmp_seq=0 ttl=64 time=1.234 ms\n\n--- 192.0.2.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0.0% packet loss\nround-trip min/avg/max/stddev = 1.234/1.234/1.234/0.000 ms\n";
    const MACOS_TIMEOUT: &str = "PING 192.0.2.99 (192.0.2.99): 56 data bytes\n\n--- 192.0.2.99 ping statistics ---\n1 packets transmitted, 0 packets received, 100.0% packet loss\n";
    const LINUX: &str = "PING 192.0.2.20 (192.0.2.20) 56(84) bytes of data.\n64 bytes from 192.0.2.20: icmp_seq=1 ttl=63 time=0.412 ms\n\n--- 192.0.2.20 ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\nrtt min/avg/max/mdev = 0.412/0.412/0.412/0.000 ms\n";
    const LINUX_UNREACHABLE: &str = "PING 192.0.2.77 (192.0.2.77) 56(84) bytes of data.\nFrom 192.0.2.10 icmp_seq=1 Destination Host Unreachable\n\n--- 192.0.2.77 ping statistics ---\n1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n";
    const BUSYBOX: &str =
        "PING 198.51.100.1 (198.51.100.1): 56 data bytes\n64 bytes from 198.51.100.1: seq=0 ttl=255 time=2.100 ms\n";
    const WINDOWS_FR: &str = "\r\nEnvoi d’une requête 'Ping'  192.0.2.1 avec 32 octets de données :\r\nRéponse de 192.0.2.1 : octets=32 temps<1ms TTL=64\r\n\r\nStatistiques Ping pour 192.0.2.1:\r\n    Paquets : envoyés = 1, reçus = 1, perdus = 0 (perte 0%),\r\nDurée approximative des boucles en millisecondes :\r\n    Minimum = 0ms, Maximum = 0ms, Moyenne = 0ms\r\n";
    const WINDOWS_FR_SLOW: &str = "Réponse de 203.0.113.3 : octets=32 temps=17 ms TTL=128\r\n";
    const WINDOWS_EN_UNREACHABLE: &str = "\r\nPinging 192.0.2.77 with 32 bytes of data:\r\nReply from 192.0.2.10: Destination host unreachable.\r\n\r\nPing statistics for 192.0.2.77:\r\n    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),\r\n";
    const WINDOWS_FR_TIMEOUT: &str = "Envoi d’une requête 'Ping'  198.51.100.9 avec 32 octets de données :\r\nDélai d’attente de la demande dépassé.\r\n";
    const WINDOWS_DE: &str = "Antwort von 203.0.113.1: Bytes=32 Zeit=3ms TTL=64\r\n";
    const WINDOWS_TTL_EXPIRED: &str = "Réponse de 198.51.100.1 : TTL expiré lors du transit.\r\n";
    const LINUX_COMMA_LOCALE: &str = "64 octets de 192.0.2.1 : icmp_seq=1 ttl=64 temps=1,52 ms\n";

    #[test]
    fn unix_replies() {
        assert_eq!(parse_ping(MACOS), PingParse { ttl: Some(64), latency_ms: Some(1.234) });
        assert_eq!(parse_ping(LINUX), PingParse { ttl: Some(63), latency_ms: Some(0.412) });
        assert_eq!(parse_ping(BUSYBOX), PingParse { ttl: Some(255), latency_ms: Some(2.1) });
        assert_eq!(parse_ping(LINUX_COMMA_LOCALE), PingParse { ttl: Some(64), latency_ms: Some(1.52) });
    }

    #[test]
    fn unix_failures() {
        assert!(!parse_ping(MACOS_TIMEOUT).replied());
        assert!(!parse_ping(LINUX_UNREACHABLE).replied());
        assert!(!parse_ping("").replied());
    }

    #[test]
    fn windows_localized() {
        assert_eq!(parse_ping(WINDOWS_FR), PingParse { ttl: Some(64), latency_ms: Some(1.0) });
        assert_eq!(parse_ping(WINDOWS_FR_SLOW), PingParse { ttl: Some(128), latency_ms: Some(17.0) });
        assert_eq!(parse_ping(WINDOWS_DE), PingParse { ttl: Some(64), latency_ms: Some(3.0) });
        assert!(!parse_ping(WINDOWS_EN_UNREACHABLE).replied(), "« unreachable » renvoie 0 sous Windows");
        assert!(!parse_ping(WINDOWS_FR_TIMEOUT).replied());
        assert!(!parse_ping(WINDOWS_TTL_EXPIRED).replied());
    }

    #[test]
    fn hostile_values() {
        assert!(!parse_ping("ttl=999 time=1 ms").replied());
        assert_eq!(parse_ping("ttl=64 time=abc ms").latency_ms, None);
        assert_eq!(parse_ping("TTL : 64").ttl, Some(64));
    }
}
