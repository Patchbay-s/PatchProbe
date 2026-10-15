//! Extraction du `<title>` HTML des services auto-hébergés — port de `WebServiceIdentifier`.

/// Ports essayés en premier (interfaces auto-hébergées courantes), puis les autres.
pub const PRIORITY_PORTS: [u16; 19] =
    [8123, 8006, 32400, 8989, 7878, 8686, 9696, 5055, 8096, 8112, 9091, 8181, 3000, 9000, 1880, 6052, 8081, 8000, 9443];

/// Ports servis uniquement en HTTPS.
pub const HTTPS_ONLY_PORTS: [u16; 6] = [443, 8443, 9443, 4443, 8006, 10000];

/// Ports à interroger, dans l'ordre (prioritaires d'abord), au plus `limit`.
pub fn ordered_ports(open_ports: &[u16], limit: usize) -> Vec<u16> {
    let mut ordered: Vec<u16> = PRIORITY_PORTS.iter().copied().filter(|p| open_ports.contains(p)).collect();
    ordered.extend(open_ports.iter().copied().filter(|p| !PRIORITY_PORTS.contains(p)));
    ordered.dedup();
    ordered.truncate(limit);
    ordered
}

pub fn scheme_for_title_port(port: u16) -> &'static str {
    if HTTPS_ONLY_PORTS.contains(&port) {
        "https"
    } else {
        "http"
    }
}

fn find_ci(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let lower = haystack.get(from..)?.to_ascii_lowercase();
    lower.find(needle).map(|pos| pos + from)
}

/// Contenu de `<title …>…</title>` (insensible à la casse), entités de base décodées, espaces
/// normalisés. `None` si absent ou vide.
pub fn extract_title(html: &str) -> Option<String> {
    let start = find_ci(html, "<title", 0)?;
    let open_end = html.get(start..)?.find('>')? + start + 1;
    let end = find_ci(html, "</title", open_end)?;
    let raw = html.get(open_end..end)?;
    let decoded = decode_entities(raw);
    let collapsed = decoded.split_whitespace().collect::<Vec<_>>().join(" ");
    let title: String = collapsed.chars().filter(|c| !c.is_control()).take(120).collect();
    (!title.is_empty()).then_some(title)
}

fn decode_entities(text: &str) -> String {
    let mut result = text.to_owned();
    for (entity, replacement) in [
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", "\""),
        ("&#39;", "'"),
        ("&#039;", "'"),
        ("&apos;", "'"),
        ("&nbsp;", " "),
        ("&amp;", "&"),
    ] {
        result = result.replace(entity, replacement);
    }
    result
}

/// Décode des octets HTML : UTF-8, sinon Latin-1 (chaque octet est un caractère).
pub fn decode_body(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        // Un préfixe tronqué au milieu d'un caractère UTF-8 reste lisible en lossy.
        Err(e) if e.error_len().is_none() => String::from_utf8_lossy(bytes).into_owned(),
        Err(_) => bytes.iter().map(|b| char::from(*b)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_vectors() {
        assert_eq!(
            extract_title("<html><head><title>Home Assistant</title></head></html>").as_deref(),
            Some("Home Assistant")
        );
        assert_eq!(extract_title("<title>\n  Sonarr  \n</title>").as_deref(), Some("Sonarr"));
        assert_eq!(extract_title("<title>Tom &amp; Jerry&#39;s NAS</title>").as_deref(), Some("Tom & Jerry's NAS"));
        assert_eq!(
            extract_title("<HTML><HEAD><TITLE>Router Admin</TITLE></HEAD></HTML>").as_deref(),
            Some("Router Admin")
        );
        assert_eq!(
            extract_title("<title lang=\"en\">Proxmox Virtual Environment</title>").as_deref(),
            Some("Proxmox Virtual Environment")
        );
        assert_eq!(extract_title("<html><body>no title here</body></html>"), None);
        assert_eq!(extract_title("<title></title>"), None);
        assert_eq!(extract_title("<title>   </title>"), None);
        assert_eq!(extract_title("<title>pas de fin"), None);
    }

    #[test]
    fn handles_non_ascii_without_panicking() {
        assert_eq!(extract_title("<TİTLE>x</title><title>Test Device</title>").as_deref(), Some("Test Device"));
        assert_eq!(extract_title("é<title>Box Internet — Accueil</title>").as_deref(), Some("Box Internet — Accueil"));
    }

    #[test]
    fn port_ordering_and_scheme() {
        assert_eq!(ordered_ports(&[22, 80, 8123, 443], 10), [8123, 22, 80, 443]);
        assert_eq!(ordered_ports(&[22, 80, 8123, 443], 2), [8123, 22]);
        assert_eq!(scheme_for_title_port(8006), "https");
        assert_eq!(scheme_for_title_port(80), "http");
    }

    #[test]
    fn decodes_latin1_fallback() {
        assert_eq!(decode_body(&[b'C', b'a', b'f', 0xE9, b'!']), "Café!");
        assert_eq!(decode_body("Café".as_bytes()), "Café");
    }
}
