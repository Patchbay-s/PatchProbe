//! SSDP/UPnP : M-SEARCH, en-têtes de réponse et `friendlyName` du descripteur — port de
//! `SSDPDiscoveryService.swift`.

use std::net::Ipv4Addr;

pub const MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const PORT: u16 = 1900;

pub fn m_search_request() -> &'static [u8] {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n"
}

/// Valeur d'un en-tête (nom insensible à la casse).
pub fn header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.split("\r\n").chain(response.split('\n')).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// N'accepte que les URL http(s) dont l'hôte est l'appareil qui a répondu : un équipement du
/// LAN ne doit pas pouvoir nous faire interroger une autre machine.
pub fn validated_location(location: &str, responder: Ipv4Addr) -> Option<String> {
    let rest = location.strip_prefix("http://").or_else(|| location.strip_prefix("https://"))?;
    let authority = rest.split('/').next()?;
    let host = authority.rsplit_once(':').map_or(authority, |(host, port)| {
        if port.bytes().all(|b| b.is_ascii_digit()) {
            host
        } else {
            authority
        }
    });
    (host.parse::<Ipv4Addr>().ok()? == responder).then(|| location.to_owned())
}

/// `<friendlyName>…</friendlyName>` du descripteur XML.
pub fn extract_friendly_name(xml: &str) -> Option<String> {
    let start = xml.find("<friendlyName>")? + "<friendlyName>".len();
    let end = xml.get(start..)?.find("</friendlyName>")? + start;
    let raw = xml.get(start..end)?;
    let decoded = raw.replace("&amp;", "&").replace("&apos;", "'").replace("&quot;", "\"");
    super::sanitize_name(&decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESPONSE: &str = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.0.2.20:49152/description.xml\r\nST: upnp:rootdevice\r\n\r\n";

    #[test]
    fn reads_headers_case_insensitively() {
        assert_eq!(header(RESPONSE, "LOCATION"), Some("http://192.0.2.20:49152/description.xml"));
        assert_eq!(header(RESPONSE, "st"), Some("upnp:rootdevice"));
        assert_eq!(header(RESPONSE, "server"), None);
    }

    #[test]
    fn location_must_point_to_responder() {
        let ip = Ipv4Addr::new(192, 0, 2, 20);
        assert!(validated_location("http://192.0.2.20:49152/description.xml", ip).is_some());
        assert!(validated_location("http://192.0.2.20/d.xml", ip).is_some());
        assert!(validated_location("http://198.51.100.1:80/d.xml", ip).is_none());
        assert!(validated_location("file:///etc/passwd", ip).is_none());
        assert!(validated_location("http://evil.example/d.xml", ip).is_none());
    }

    #[test]
    fn extracts_friendly_name() {
        let xml = "<root><device><friendlyName> Test Media Device </friendlyName></device></root>";
        assert_eq!(extract_friendly_name(xml).as_deref(), Some("Test Media Device"));
        assert_eq!(extract_friendly_name("<root/>"), None);
        assert_eq!(extract_friendly_name("<friendlyName></friendlyName>"), None);
    }
}
