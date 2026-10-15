//! Parsing des ports TCP et presets par type d'appareil — port de `ScanViewModel.parsePorts`,
//! `PortScanner.defaultPorts` et `PortPreset.swift`.
//!
//! Tout passe par `u32` puis `u16::try_from` : aucun cast tronquant, aucun panic sur saisie.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Plafond du nombre total de ports (dédoublonnés) d'une saisie.
pub const MAX_PORT_COUNT: usize = 5000;

/// Liste par défaut orientée services classiques + self-hosted/homelab.
pub const DEFAULT_TCP_PORTS: [u16; 39] = [
    21, 22, 23, 25, 53, 80, 81, 110, 143, 443, 445, 631, 1880, 3000, 3306, 3389, 5000, 5001, 5055, 5432, 6052, 7878,
    8000, 8006, 8080, 8081, 8096, 8112, 8123, 8181, 8443, 8686, 8989, 9000, 9091, 9443, 9696, 19999, 32400,
];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortParseError {
    #[error("Aucun port saisi.")]
    Empty,
    #[error("« {0} » n'est pas un numéro de port.")]
    NotANumber(String),
    #[error("Port hors limites : « {0} » (attendu entre 1 et 65535).")]
    OutOfRange(String),
    #[error("Plage de ports inversée : « {0} ».")]
    Inverted(String),
    #[error("Trop de ports : {count} (maximum {max}).")]
    TooMany { count: usize, max: usize },
}

fn parse_port(text: &str, piece: &str) -> Result<u16, PortParseError> {
    let text = text.trim();
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PortParseError::NotANumber(piece.to_owned()));
    }
    // Plus de 5 chiffres : forcément hors limites (évite tout débordement au parse).
    if text.len() > 5 {
        return Err(PortParseError::OutOfRange(piece.to_owned()));
    }
    let value: u32 = text.parse().map_err(|_| PortParseError::NotANumber(piece.to_owned()))?;
    match u16::try_from(value) {
        Ok(port) if port >= 1 => Ok(port),
        _ => Err(PortParseError::OutOfRange(piece.to_owned())),
    }
}

/// Un port seul (`8080`) ou une plage (`1-1024`).
pub fn parse_port_range(input: &str) -> Result<(u16, u16), PortParseError> {
    let piece = input.trim();
    if piece.is_empty() {
        return Err(PortParseError::Empty);
    }
    match piece.split_once('-') {
        Some((low, high)) => {
            let low = parse_port(low, piece)?;
            let high = parse_port(high, piece)?;
            if low > high {
                return Err(PortParseError::Inverted(piece.to_owned()));
            }
            let count = usize::from(high - low) + 1;
            if count > MAX_PORT_COUNT {
                return Err(PortParseError::TooMany { count, max: MAX_PORT_COUNT });
            }
            Ok((low, high))
        }
        None => {
            let port = parse_port(piece, piece)?;
            Ok((port, port))
        }
    }
}

/// Liste séparée par virgules de ports seuls et/ou de plages, ex. `554,80,8000-8010,443`.
/// Résultat dédoublonné et trié. Chaque élément doit être valide ; le total est plafonné.
pub fn parse_ports(input: &str) -> Result<Vec<u16>, PortParseError> {
    let pieces: Vec<&str> = input.split(',').map(str::trim).filter(|piece| !piece.is_empty()).collect();
    if pieces.is_empty() {
        return Err(PortParseError::Empty);
    }
    let mut ports = BTreeSet::new();
    for piece in pieces {
        let (low, high) = parse_port_range(piece)?;
        ports.extend(low..=high);
        if ports.len() > MAX_PORT_COUNT {
            return Err(PortParseError::TooMany { count: ports.len(), max: MAX_PORT_COUNT });
        }
    }
    Ok(ports.into_iter().collect())
}

/// Champ « Ports » de la barre d'outils : vide → liste par défaut, sinon [`parse_ports`].
pub fn resolve_ports(input: &str) -> Result<Vec<u16>, PortParseError> {
    if input.trim().is_empty() {
        Ok(DEFAULT_TCP_PORTS.to_vec())
    } else {
        parse_ports(input)
    }
}

/// Presets de ports par type d'appareil (identifiants identiques aux `rawValue` Swift).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortPresetKind {
    #[serde(rename = "cameraIP")]
    CameraIp,
    #[serde(rename = "generic")]
    Generic,
    #[serde(rename = "webServer")]
    WebServer,
    #[serde(rename = "printer")]
    Printer,
    #[serde(rename = "nas")]
    Nas,
}

impl PortPresetKind {
    pub const ALL: [PortPresetKind; 5] = [Self::CameraIp, Self::Generic, Self::WebServer, Self::Printer, Self::Nas];

    pub fn label(self) -> &'static str {
        match self {
            Self::CameraIp => "Caméra IP",
            Self::Generic => "Générique / Homelab",
            Self::WebServer => "Serveur web",
            Self::Printer => "Imprimante",
            Self::Nas => "NAS",
        }
    }

    pub fn ports(self) -> &'static [u16] {
        match self {
            Self::CameraIp => &[554, 80, 8000, 8080, 443],
            Self::Generic => &DEFAULT_TCP_PORTS,
            Self::WebServer => &[80, 443, 8080, 8443],
            Self::Printer => &[9100, 515, 631],
            Self::Nas => &[445, 139, 2049, 5000, 5001],
        }
    }

    /// Texte à placer dans le champ « Ports » (ordre du preset conservé).
    pub fn ports_string(self) -> String {
        self.ports().iter().map(u16::to_string).collect::<Vec<_>>().join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_range_and_single_port() {
        assert_eq!(parse_port_range("1-1024"), Ok((1, 1024)));
        assert_eq!(parse_port_range("8080"), Ok((8080, 8080)));
        assert_eq!(parse_port_range(" 22 - 25 "), Ok((22, 25)));
    }

    #[test]
    fn rejects_inverted_out_of_bounds_and_garbage() {
        assert!(matches!(parse_port_range("1024-1"), Err(PortParseError::Inverted(_))));
        assert!(matches!(parse_port_range("0-100"), Err(PortParseError::OutOfRange(_))));
        assert!(matches!(parse_port_range("1-70000"), Err(PortParseError::OutOfRange(_))));
        assert!(matches!(parse_port_range("99999999999999999999"), Err(PortParseError::OutOfRange(_))));
        assert!(matches!(parse_port_range("abc"), Err(PortParseError::NotANumber(_))));
        assert!(matches!(parse_port_range("-5"), Err(PortParseError::NotANumber(_))));
        assert!(matches!(parse_port_range("+5"), Err(PortParseError::NotANumber(_))));
        assert!(matches!(parse_port_range("1-2-3"), Err(PortParseError::NotANumber(_))));
        assert_eq!(parse_port_range(""), Err(PortParseError::Empty));
        assert!(matches!(parse_port_range("1-5001"), Err(PortParseError::TooMany { .. })));
    }

    #[test]
    fn parses_comma_lists() {
        assert_eq!(parse_ports("554,80,8000,8080,443").unwrap(), [80, 443, 554, 8000, 8080]);
        assert_eq!(parse_ports("22,8000-8002").unwrap(), [22, 8000, 8001, 8002]);
        assert_eq!(parse_ports("8080").unwrap(), [8080]);
        assert_eq!(parse_ports("1-10").unwrap(), (1..=10).collect::<Vec<_>>());
        assert_eq!(parse_ports("80,80,443").unwrap(), [80, 443]);
        assert_eq!(parse_ports("80,,443,").unwrap(), [80, 443]);
    }

    #[test]
    fn rejects_bad_lists() {
        assert!(matches!(parse_ports("80,abc"), Err(PortParseError::NotANumber(_))));
        assert_eq!(parse_ports(""), Err(PortParseError::Empty));
        assert_eq!(parse_ports(" , "), Err(PortParseError::Empty));
        assert!(matches!(parse_ports("1-4999,5000-5001"), Err(PortParseError::TooMany { .. })));
        assert_eq!(parse_ports("1-5000").unwrap().len(), 5000);
    }

    #[test]
    fn resolve_uses_defaults_when_empty() {
        assert_eq!(resolve_ports("  ").unwrap(), DEFAULT_TCP_PORTS.to_vec());
        assert!(resolve_ports("x").is_err());
    }

    #[test]
    fn presets_match_swift() {
        assert_eq!(PortPresetKind::CameraIp.ports(), [554, 80, 8000, 8080, 443]);
        assert_eq!(PortPresetKind::Generic.ports(), DEFAULT_TCP_PORTS);
        assert_eq!(PortPresetKind::WebServer.ports(), [80, 443, 8080, 8443]);
        assert_eq!(PortPresetKind::Printer.ports(), [9100, 515, 631]);
        assert_eq!(PortPresetKind::Nas.ports(), [445, 139, 2049, 5000, 5001]);
        assert_eq!(PortPresetKind::CameraIp.ports_string(), "554,80,8000,8080,443");
        for kind in PortPresetKind::ALL {
            assert!(parse_ports(&kind.ports_string()).is_ok(), "{kind:?}");
        }
        assert_eq!(serde_json::to_string(&PortPresetKind::CameraIp).unwrap(), "\"cameraIP\"");
    }
}
