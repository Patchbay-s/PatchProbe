//! Parseur de la sortie XML de nmap (`-oX -`) — port de `NmapXMLParserDelegate`.

use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NmapPort {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

impl NmapPort {
    /// Identifiant unique : `tcp/53` et `udp/53` sont distincts.
    pub fn id(&self) -> String {
        format!("{}/{}", self.protocol, self.port)
    }

    /// « service produit version », champs vides ignorés.
    pub fn summary(&self) -> String {
        [&self.service, &self.product, &self.version]
            .into_iter()
            .flatten()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NmapReport {
    pub ports: Vec<NmapPort>,
    /// Noms d'hôte rapportés par nmap (`<hostname name=…>`).
    pub hostnames: Vec<String>,
    /// `up`/`down` d'après `<status state=…>`.
    pub host_state: Option<String>,
}

#[derive(Default)]
struct PortBuilder {
    port: Option<u16>,
    protocol: Option<String>,
    state: Option<String>,
    service: Option<String>,
    product: Option<String>,
    version: Option<String>,
}

fn attr(element: &BytesStart<'_>, name: &[u8]) -> Option<String> {
    element
        .attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name)
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// Parse tolérant : un document tronqué ou invalide rend les ports lus jusque-là ; un port
/// sans `<state>` (ou sans protocole/numéro valide) est ignoré.
pub fn parse_nmap_xml(xml: &str) -> NmapReport {
    let mut reader = Reader::from_str(xml);
    let mut report = NmapReport::default();
    let mut current: Option<PortBuilder> = None;
    loop {
        let event = match reader.read_event() {
            Ok(Event::Eof) | Err(_) => break,
            Ok(event) => event,
        };
        let (element, is_empty) = match &event {
            Event::Start(e) => (Some(e), false),
            Event::Empty(e) => (Some(e), true),
            _ => (None, false),
        };
        if let Some(e) = element {
            match e.name().as_ref() {
                b"port" => {
                    current = Some(PortBuilder {
                        port: attr(e, b"portid").and_then(|p| p.parse().ok()),
                        protocol: attr(e, b"protocol"),
                        ..PortBuilder::default()
                    });
                    if is_empty {
                        current = None; // <port/> sans état : ignoré
                    }
                }
                b"state" => {
                    if let Some(builder) = current.as_mut() {
                        builder.state = attr(e, b"state");
                    }
                }
                b"service" => {
                    if let Some(builder) = current.as_mut() {
                        builder.service = attr(e, b"name");
                        builder.product = attr(e, b"product");
                        builder.version = attr(e, b"version");
                    }
                }
                b"hostname" => {
                    if let Some(name) = attr(e, b"name").filter(|n| !n.is_empty()) {
                        if !report.hostnames.contains(&name) {
                            report.hostnames.push(name);
                        }
                    }
                }
                b"status" => report.host_state = attr(e, b"state"),
                _ => {}
            }
        }
        if let Event::End(e) = &event {
            if e.name().as_ref() == b"port" {
                if let Some(PortBuilder {
                    port: Some(port),
                    protocol: Some(protocol),
                    state: Some(state),
                    service,
                    product,
                    version,
                }) = current.take()
                {
                    report.ports.push(NmapPort { port, protocol, state, service, product, version });
                }
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_open_ports_with_service_details() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up" reason="user-set"/>
    <hostnames><hostname name="storage.example.invalid" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.24.0" method="probed"/>
      </port>
    </ports>
  </host>
</nmaprun>"#;
        let report = parse_nmap_xml(xml);
        assert_eq!(report.ports.len(), 2);
        let ssh = &report.ports[0];
        assert_eq!((ssh.port, ssh.protocol.as_str(), ssh.state.as_str()), (22, "tcp", "open"));
        assert_eq!(ssh.service.as_deref(), Some("ssh"));
        assert_eq!(ssh.product.as_deref(), Some("OpenSSH"));
        assert_eq!(ssh.version.as_deref(), Some("8.9p1"));
        assert_eq!(ssh.summary(), "ssh OpenSSH 8.9p1");
        assert_eq!(report.ports[1].service.as_deref(), Some("http"));
        assert_eq!(report.hostnames, ["storage.example.invalid"]);
        assert_eq!(report.host_state.as_deref(), Some("up"));
    }

    #[test]
    fn port_without_service() {
        let xml = r#"<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="filtered" reason="no-response"/></port></ports></host></nmaprun>"#;
        let report = parse_nmap_xml(xml);
        assert_eq!(report.ports.len(), 1);
        assert_eq!(report.ports[0].state, "filtered");
        assert_eq!(report.ports[0].service, None);
        assert_eq!(report.ports[0].summary(), "");
    }

    #[test]
    fn malformed_and_missing_attributes() {
        assert!(parse_nmap_xml("not xml at all").ports.is_empty());
        assert!(parse_nmap_xml("").ports.is_empty());
        let xml = r#"<nmaprun><host><ports><port protocol="tcp" portid="8080"></port></ports></host></nmaprun>"#;
        assert!(parse_nmap_xml(xml).ports.is_empty());
        let xml = r#"<nmaprun><port protocol="tcp" portid="99999"><state state="open"/></port></nmaprun>"#;
        assert!(parse_nmap_xml(xml).ports.is_empty(), "portid hors u16");
    }

    #[test]
    fn unique_ids_and_truncated_document() {
        let xml = r#"<nmaprun><host><ports>
  <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
  <port protocol="udp" portid="53"><state state="open"/><service name="domain"/></port>
  <port protocol="tcp" portid="80"><state state="op"#;
        let report = parse_nmap_xml(xml);
        assert_eq!(report.ports.len(), 2);
        assert_ne!(report.ports[0].id(), report.ports[1].id());
    }

    #[test]
    fn unescapes_attributes() {
        let xml = r#"<nmaprun><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Caddy &amp; co"/></port></nmaprun>"#;
        assert_eq!(parse_nmap_xml(xml).ports[0].product.as_deref(), Some("Caddy & co"));
    }
}
