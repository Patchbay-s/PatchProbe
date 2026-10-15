//! Classification grossière du type d'appareil — port de `DeviceType.swift`. Purement cosmétique
//! (icône dans la table), au mieux et parfois faux.

use serde::{Deserialize, Serialize};

use crate::ttl::{OS_LINUX_MACOS, OS_NETWORK_GEAR, OS_WINDOWS};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DeviceType {
    Router,
    Camera,
    Printer,
    Phone,
    Computer,
    Nas,
    Media,
    Iot,
    NetworkGear,
    #[default]
    Unknown,
}

impl DeviceType {
    pub fn label(self) -> &'static str {
        match self {
            Self::Router => "Routeur",
            Self::Camera => "Caméra",
            Self::Printer => "Imprimante",
            Self::Phone => "Téléphone/Tablette",
            Self::Computer => "Ordinateur",
            Self::Nas => "NAS",
            Self::Media => "Média/Streaming",
            Self::Iot => "Objet connecté",
            Self::NetworkGear => "Équipement réseau",
            Self::Unknown => "Type inconnu",
        }
    }

    /// L'ordre compte : les signaux spécifiques (hostname, ports dédiés) passent avant le repli
    /// sur l'OS (un iPhone et un Mac ont le même fabricant « Apple, Inc. »).
    pub fn classify(
        vendor: Option<&str>,
        hostname: Option<&str>,
        probable_os: Option<&str>,
        open_ports: &[u16],
    ) -> Self {
        let v = vendor.unwrap_or_default().to_lowercase();
        let h = hostname.unwrap_or_default().to_lowercase();
        let has_port = |port: u16| open_ports.contains(&port);

        if contains_any(&h, &["iphone", "ipad", "android", "galaxy", "pixel", "smartphone"]) {
            return Self::Phone;
        }
        if contains_any(&v, &["hikvision", "dahua", "axis communications", "reolink", "amcrest", "foscam"])
            || has_port(554)
        {
            return Self::Camera;
        }
        if contains_any(&v, &["hewlett", "canon", "epson", "brother industries", "xerox", "lexmark"])
            || has_port(631)
            || has_port(9100)
        {
            return Self::Printer;
        }
        if contains_any(&v, &["synology", "qnap"]) || h.contains("nas") {
            return Self::Nas;
        }
        if contains_any(&v, &["sonos", "roku"]) || contains_any(&h, &["chromecast", "appletv", "apple tv", "plex"]) {
            return Self::Media;
        }
        if contains_any(&v, &["espressif", "tuya", "sonoff"])
            || contains_any(&h, &["sonoff", "shelly", "tasmota", "esp32", "esp8266"])
        {
            return Self::Iot;
        }
        if contains_any(&v, &["freebox", "cisco", "netgear", "tp-link", "ubiquiti", "d-link", "asustek", "sagemcom"])
            || contains_any(&h, &["router", "freebox", "livebox", "gateway"])
        {
            return Self::Router;
        }
        match probable_os {
            Some(os) if os == OS_NETWORK_GEAR => Self::NetworkGear,
            Some(os) if os == OS_WINDOWS || os == OS_LINUX_MACOS => Self::Computer,
            _ => Self::Unknown,
        }
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::DeviceType as D;

    #[test]
    fn swift_vectors() {
        assert_eq!(D::classify(Some("Apple, Inc."), Some("iphone-01.example.invalid"), None, &[]), D::Phone);
        assert_eq!(D::classify(Some("Hikvision"), None, None, &[]), D::Camera);
        assert_eq!(D::classify(None, None, None, &[554]), D::Camera);
        assert_eq!(D::classify(None, None, None, &[631]), D::Printer);
        assert_eq!(D::classify(Some("Synology Inc."), None, None, &[]), D::Nas);
        assert_eq!(D::classify(Some("Cisco Systems, Inc"), None, None, &[]), D::Router);
        assert_eq!(D::classify(None, None, Some("Windows"), &[]), D::Computer);
        assert_eq!(D::classify(None, None, Some("Linux/macOS"), &[]), D::Computer);
        assert_eq!(D::classify(None, None, Some("Équipement réseau"), &[]), D::NetworkGear);
        assert_eq!(D::classify(None, None, None, &[]), D::Unknown);
        assert_eq!(D::classify(Some("HIKVISION DIGITAL TECHNOLOGY"), None, None, &[]), D::Camera);
    }

    #[test]
    fn labels() {
        assert_eq!(D::Router.label(), "Routeur");
        assert_eq!(D::Unknown.label(), "Type inconnu");
    }
}
