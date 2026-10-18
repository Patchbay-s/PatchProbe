//! Réglages persistés de l'application (timing, ports, plages récentes, affichage).

use serde::{Deserialize, Serialize};

use crate::model::grouping::GroupingOption;
use crate::ports::PortPresetKind;
use crate::settings::ScanSettings;

pub const MAX_RECENT_RANGES: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub scan: ScanSettings,
    /// Dernier preset de ports choisi, réappliqué au lancement.
    pub last_port_preset: Option<PortPresetKind>,
    /// Contenu du champ « Ports ».
    pub ports_input: String,
    /// Plages récentes, la plus récente d'abord, sans doublon.
    pub recent_ranges: Vec<String>,
    pub hide_down_hosts: bool,
    pub grouping: GroupingOption,
    /// Terminal utilisé pour SSH : `auto` (terminal par défaut du système) ou un identifiant.
    pub ssh_terminal: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            scan: ScanSettings::default(),
            last_port_preset: None,
            ports_input: String::new(),
            recent_ranges: Vec::new(),
            hide_down_hosts: true,
            grouping: GroupingOption::None,
            ssh_terminal: "auto".to_owned(),
        }
    }
}

impl AppSettings {
    pub fn remember_recent_range(&mut self, range: &str) {
        let range = range.trim();
        if range.is_empty() {
            return;
        }
        self.recent_ranges.retain(|r| r != range);
        self.recent_ranges.insert(0, range.to_owned());
        self.recent_ranges.truncate(MAX_RECENT_RANGES);
    }

    pub fn apply_port_preset(&mut self, kind: PortPresetKind) {
        self.ports_input = kind.ports_string();
        self.last_port_preset = Some(kind);
    }

    pub fn sanitized(mut self) -> Self {
        self.scan = self.scan.sanitized();
        self.recent_ranges.truncate(MAX_RECENT_RANGES);
        let valid = !self.ssh_terminal.is_empty()
            && self.ssh_terminal.len() <= 32
            && self.ssh_terminal.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid {
            self.ssh_terminal = "auto".to_owned();
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recent_ranges_front_dedup_and_cap() {
        let mut s = AppSettings::default();
        s.remember_recent_range("192.0.2.0/24");
        s.remember_recent_range("198.51.100.1-254");
        assert_eq!(s.recent_ranges, ["198.51.100.1-254", "192.0.2.0/24"]);
        s.remember_recent_range("192.0.2.0/24");
        assert_eq!(s.recent_ranges, ["192.0.2.0/24", "198.51.100.1-254"]);
        for i in 1..=7 {
            s.remember_recent_range(&format!("198.51.100.{i}"));
        }
        assert_eq!(s.recent_ranges.len(), 5);
        assert_eq!(s.recent_ranges[0], "198.51.100.7");
    }

    #[test]
    fn persists_through_json_and_tolerates_missing_fields() {
        let mut s = AppSettings::default();
        s.apply_port_preset(PortPresetKind::Nas);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<AppSettings>(&json).unwrap(), s);
        let partial: AppSettings = serde_json::from_str(r#"{"hideDownHosts": false}"#).unwrap();
        assert!(!partial.hide_down_hosts);
        assert_eq!(partial.scan, ScanSettings::approfondi());
        assert_eq!(s.ports_input, "445,139,2049,5000,5001");
        assert_eq!(partial.ssh_terminal, "auto");
    }

    #[test]
    fn invalid_ssh_terminal_falls_back_to_auto() {
        let mut s = AppSettings { ssh_terminal: "x; calc".into(), ..AppSettings::default() };
        assert_eq!(s.clone().sanitized().ssh_terminal, "auto");
        s.ssh_terminal = "iterm".into();
        assert_eq!(s.sanitized().ssh_terminal, "iterm");
    }
}
