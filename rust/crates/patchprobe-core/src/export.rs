//! Exports CSV, JSON et HTML — port de `CSVExportService`, `JSONExportService`,
//! `HTMLExportService`.

use serde::Serialize;

use crate::model::{Host, HostStatus};

pub const CSV_HEADER: &str = "IP,Statut,Hostname,Latence(ms),Ports ouverts,MAC,Fabricant";

fn export_status(status: HostStatus) -> &'static str {
    match status {
        HostStatus::Up => "En ligne",
        HostStatus::Down => "Hors ligne",
        HostStatus::Scanning => "Scan en cours",
        HostStatus::Unknown => "Inconnu",
    }
}

/// Neutralise l'injection de formule (tableurs) puis applique le quoting RFC 4180. Les champs
/// viennent du réseau (hostname mDNS/NBNS/titre web…) : un `=…` ne doit jamais être évalué.
pub fn csv_field(field: &str) -> String {
    let mut field = field.to_owned();
    if field.starts_with(['=', '+', '-', '@', ' ', '\t', '\r', '\n']) {
        field.insert(0, '\'');
    }
    if field.contains([',', '"', '\n', '\r', ';']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field
    }
}

pub fn csv(hosts: &[Host]) -> String {
    let mut lines = vec![CSV_HEADER.to_owned()];
    for host in hosts {
        let latency = host.latency_ms.map(|ms| format!("{ms:.0}")).unwrap_or_default();
        let ports = host.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(";");
        let fields = [
            host.ip.to_string(),
            export_status(host.status).to_owned(),
            host.hostname.clone().unwrap_or_default(),
            latency,
            ports,
            host.mac.clone().unwrap_or_default(),
            host.vendor.clone().unwrap_or_default(),
        ];
        // Les ports « 80;443 » sont produits par nous : pas de guillemets superflus.
        let line: Vec<String> =
            fields.iter().enumerate().map(|(index, f)| if index == 4 { f.clone() } else { csv_field(f) }).collect();
        lines.push(line.join(","));
    }
    lines.join("\n")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportedHost<'a> {
    ip: String,
    status: &'static str,
    hostname: Option<&'a str>,
    latency_ms: Option<f64>,
    open_ports: &'a [u16],
    mac: Option<&'a str>,
    vendor: Option<&'a str>,
    probable_os: Option<&'a str>,
    is_likely_routed: bool,
    device_type: &'static str,
}

/// Tableau JSON indenté, clés triées.
pub fn json(hosts: &[Host]) -> String {
    let exported: Vec<ExportedHost<'_>> = hosts
        .iter()
        .map(|h| ExportedHost {
            ip: h.ip.to_string(),
            status: match h.status {
                HostStatus::Up => "up",
                HostStatus::Down => "down",
                HostStatus::Scanning => "scanning",
                HostStatus::Unknown => "unknown",
            },
            hostname: h.hostname.as_deref(),
            latency_ms: h.latency_ms,
            open_ports: &h.open_ports,
            mac: h.mac.as_deref(),
            vendor: h.vendor.as_deref(),
            probable_os: h.probable_os.as_deref(),
            is_likely_routed: h.is_likely_routed,
            device_type: h.device_type.label(),
        })
        .collect();
    // Value (BTreeMap) → clés triées à la sérialisation.
    serde_json::to_value(&exported).and_then(|v| serde_json::to_string_pretty(&v)).unwrap_or_else(|_| "[]".to_owned())
}

/// Échappement HTML complet (texte et attributs).
pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() && c != '\n' && c != '\t' => {}
            c => out.push(c),
        }
    }
    out
}

fn html_row(host: &Host) -> String {
    let (class, status) = match host.status {
        HostStatus::Up => ("up", "En ligne"),
        HostStatus::Down => ("down", "Hors ligne"),
        HostStatus::Scanning => ("muted", "Scan en cours"),
        HostStatus::Unknown => ("muted", "Inconnu"),
    };
    let latency = host.latency_ms.map_or_else(|| "—".to_owned(), |ms| format!("{ms:.0} ms"));
    let ports = if host.open_ports.is_empty() {
        "—".to_owned()
    } else {
        host.open_ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    };
    let mac = host.mac.clone().unwrap_or_else(|| if host.is_likely_routed { "routé".into() } else { "—".into() });
    let dash = |v: &Option<String>| v.clone().unwrap_or_else(|| "—".into());
    format!(
        "<tr>\n<td class=\"{class}\">{}</td>\n<td><code>{}</code></td>\n<td>{}</td>\n<td>{}</td>\n<td>{}</td>\n<td><code>{}</code></td>\n<td>{}</td>\n<td>{}</td>\n</tr>",
        html_escape(status),
        html_escape(&host.ip.to_string()),
        html_escape(&dash(&host.hostname)),
        html_escape(&latency),
        html_escape(&dash(&host.probable_os)),
        html_escape(&mac),
        html_escape(&dash(&host.vendor)),
        html_escape(&ports),
    )
}

/// Rapport HTML autonome ; `generated_at` est déjà formaté pour l'affichage.
pub fn html(hosts: &[Host], range_input: &str, generated_at: &str) -> String {
    let rows = hosts.iter().map(html_row).collect::<Vec<_>>().join("\n");
    format!(
        r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Rapport PatchProbe — {range}</title>
<style>
body {{ font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2rem; color: #1c1c1e; }}
h1 {{ font-size: 1.4rem; }}
.meta {{ color: #6e6e73; font-size: 0.9rem; margin-bottom: 1.5rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #e5e5ea; }}
th {{ background: #f5f5f7; position: sticky; top: 0; }}
.up {{ color: #248a3d; font-weight: 600; }}
.down {{ color: #d70015; }}
.muted {{ color: #8e8e93; }}
code {{ font-family: ui-monospace, monospace; }}
</style>
</head>
<body>
<h1>Rapport PatchProbe</h1>
<div class="meta">Plage : <code>{range}</code> — généré le {date} — {count} hôte(s)</div>
<table>
<thead><tr>
<th>Statut</th><th>IP</th><th>Hostname</th><th>Latence</th><th>OS probable</th><th>MAC</th><th>Fabricant</th><th>Ports ouverts</th>
</tr></thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"#,
        range = html_escape(range_input),
        date = html_escape(generated_at),
        count = hosts.len(),
    )
}

/// Suffixe de nom de fichier, ex. `2026-10-14_1530`.
pub fn timestamp_suffix(date: chrono::DateTime<chrono::Local>) -> String {
    date.format("%Y-%m-%d_%H%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(ip: &str, status: HostStatus) -> Host {
        let mut h = Host::new(ip.parse().unwrap());
        h.status = status;
        h
    }

    #[test]
    fn csv_header_and_rows() {
        assert_eq!(csv(&[]), CSV_HEADER);
        let mut up = host("192.0.2.1", HostStatus::Up);
        up.hostname = Some("router.example.invalid".into());
        up.latency_ms = Some(1.6);
        up.open_ports = vec![80, 443];
        up.mac = Some("02:00:00:00:00:01".into());
        up.vendor = Some("Netgear".into());
        let out = csv(&[up, host("192.0.2.2", HostStatus::Down)]);
        let lines: Vec<&str> = out.split('\n').collect();
        assert_eq!(lines[1], "192.0.2.1,En ligne,router.example.invalid,2,80;443,02:00:00:00:00:01,Netgear");
        assert_eq!(lines[2], "192.0.2.2,Hors ligne,,,,,");
    }

    #[test]
    fn csv_quoting() {
        let mut h = host("192.0.2.3", HostStatus::Up);
        h.vendor = Some("Apple, Inc.".into());
        h.hostname = Some("Test \"NAS\"".into());
        let out = csv(&[h]);
        assert!(out.contains("\"Apple, Inc.\""));
        assert!(out.contains("\"Test \"\"NAS\"\"\""));
    }

    #[test]
    fn csv_neutralizes_formulas() {
        for malicious in ["=1+1", "+1+1", "-1+1", "@SUM(A1:A9)", " =1+1", "\t=1"] {
            let mut h = host("192.0.2.5", HostStatus::Up);
            h.hostname = Some(malicious.into());
            let out = csv(&[h]);
            let field = out.lines().nth(1).unwrap().split(',').nth(2).unwrap();
            assert!(field.trim_start_matches('"').starts_with('\''), "{malicious:?} → {field:?}");
        }
        assert_eq!(csv_field("=HYPERLINK(\"x\")"), "\"'=HYPERLINK(\"\"x\"\")\"");
        assert_eq!(csv_field("normal"), "normal");
    }

    #[test]
    fn json_export() {
        let mut h = host("192.0.2.10", HostStatus::Up);
        h.hostname = Some("homeassistant.example.invalid".into());
        h.latency_ms = Some(5.2);
        h.open_ports = vec![80, 8123];
        h.mac = Some("02:00:00:00:00:01".into());
        h.probable_os = Some("Linux/macOS".into());
        let value: serde_json::Value = serde_json::from_str(&json(&[h])).unwrap();
        let entry = &value[0];
        assert_eq!(entry["ip"], "192.0.2.10");
        assert_eq!(entry["status"], "up");
        assert_eq!(entry["hostname"], "homeassistant.example.invalid");
        assert_eq!(entry["openPorts"], serde_json::json!([80, 8123]));
        let text = json(&[host("198.51.100.1", HostStatus::Up)]);
        assert!(text.find("\"deviceType\"") < text.find("\"ip\""), "clés triées");
        assert_eq!(serde_json::from_str::<serde_json::Value>(&json(&[])).unwrap(), serde_json::json!([]));
    }

    #[test]
    fn html_escaping_and_structure() {
        assert_eq!(html_escape("<script>"), "&lt;script&gt;");
        assert_eq!(html_escape("Tom & Jerry"), "Tom &amp; Jerry");
        assert_eq!(html_escape("say \"hi\" 'x'"), "say &quot;hi&quot; &#39;x&#39;");
        let mut h = host("192.0.2.10", HostStatus::Up);
        h.hostname = Some("<b>weird</b>".into());
        h.open_ports = vec![80, 8123];
        let page = html(&[h], "192.0.2.0/24 <x>", "14/10/2026 15:30");
        assert!(page.contains("<!DOCTYPE html>"));
        assert!(page.contains("192.0.2.10"));
        assert!(!page.contains("<b>weird</b>"));
        assert!(page.contains("&lt;b&gt;weird&lt;/b&gt;"));
        assert!(page.contains("192.0.2.0/24 &lt;x&gt;"));
        assert_eq!(page.matches("<tr>").count(), page.matches("</tr>").count());
        assert_eq!(page.matches("<table>").count(), page.matches("</table>").count());
    }
}
