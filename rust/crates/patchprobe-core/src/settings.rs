//! Réglages du scan et presets Rapide/Approfondi — port de `ScanSettings.swift`, enrichi des
//! plafonds de concurrence du moteur Rust.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TimingPreset {
    Rapide,
    Approfondi,
}

impl TimingPreset {
    pub fn label(self) -> &'static str {
        match self {
            Self::Rapide => "Rapide",
            Self::Approfondi => "Approfondi",
        }
    }
}

/// Tous les réglages qui arbitrent vitesse et exhaustivité. Les champs absents d'un fichier
/// plus ancien prennent la valeur d'« Approfondi » (`#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ScanSettings {
    pub ping_timeout_ms: u64,
    pub port_timeout_ms: u64,
    pub name_timeout_ms: u64,
    pub web_title_timeout_ms: u64,
    /// Découverte active Bonjour/SSDP en fin de scan (coût fixe ~3 s par scan, pas par hôte).
    pub runs_active_discovery: bool,
    /// Deuxième passe ARP (re-ping des hôtes vivants sans MAC puis relecture de la table).
    pub runs_arp_sweep: bool,
    /// Plafond GLOBAL de connexions TCP simultanées du scan de ports (tous hôtes confondus).
    pub max_tcp_connections: usize,
    /// Nombre d'hôtes traités en parallèle.
    pub max_parallel_hosts: usize,
    /// Budget séparé de résolutions de nom simultanées (jamais affamé par le scan de ports).
    pub max_parallel_name_resolutions: usize,
}

impl ScanSettings {
    /// « Rapide » ne resserre que les timeouts : la découverte active et la passe ARP restent
    /// actives (elles coûtent un temps fixe par scan et récupèrent l'essentiel des noms).
    pub fn rapide() -> Self {
        Self {
            ping_timeout_ms: 1000,
            port_timeout_ms: 250,
            name_timeout_ms: 500,
            web_title_timeout_ms: 800,
            ..Self::approfondi()
        }
    }

    pub fn approfondi() -> Self {
        Self {
            ping_timeout_ms: 1000,
            port_timeout_ms: 400,
            name_timeout_ms: 1000,
            web_title_timeout_ms: 1200,
            runs_active_discovery: true,
            runs_arp_sweep: true,
            max_tcp_connections: 256,
            max_parallel_hosts: 64,
            max_parallel_name_resolutions: 32,
        }
    }

    pub fn from_preset(preset: TimingPreset) -> Self {
        match preset {
            TimingPreset::Rapide => Self::rapide(),
            TimingPreset::Approfondi => Self::approfondi(),
        }
    }

    /// Applique les timeouts d'un preset en conservant les plafonds de concurrence choisis.
    pub fn apply_preset(&mut self, preset: TimingPreset) {
        let base = Self::from_preset(preset);
        self.ping_timeout_ms = base.ping_timeout_ms;
        self.port_timeout_ms = base.port_timeout_ms;
        self.name_timeout_ms = base.name_timeout_ms;
        self.web_title_timeout_ms = base.web_title_timeout_ms;
        self.runs_active_discovery = base.runs_active_discovery;
        self.runs_arp_sweep = base.runs_arp_sweep;
    }

    /// Preset dont les timeouts correspondent exactement, s'il y en a un (coche dans l'UI).
    pub fn matching_preset(&self) -> Option<TimingPreset> {
        [TimingPreset::Rapide, TimingPreset::Approfondi].into_iter().find(|preset| {
            let base = Self::from_preset(*preset);
            base.ping_timeout_ms == self.ping_timeout_ms
                && base.port_timeout_ms == self.port_timeout_ms
                && base.name_timeout_ms == self.name_timeout_ms
                && base.web_title_timeout_ms == self.web_title_timeout_ms
                && base.runs_active_discovery == self.runs_active_discovery
                && base.runs_arp_sweep == self.runs_arp_sweep
        })
    }

    /// Bornes de sécurité : un fichier de réglages édité à la main ne doit pas pouvoir demander
    /// 0 connexion (blocage) ni 1 million (épuisement des descripteurs).
    pub fn sanitized(mut self) -> Self {
        self.ping_timeout_ms = self.ping_timeout_ms.clamp(200, 10_000);
        self.port_timeout_ms = self.port_timeout_ms.clamp(50, 10_000);
        self.name_timeout_ms = self.name_timeout_ms.clamp(100, 10_000);
        self.web_title_timeout_ms = self.web_title_timeout_ms.clamp(100, 10_000);
        self.max_tcp_connections = self.max_tcp_connections.clamp(1, 4096);
        self.max_parallel_hosts = self.max_parallel_hosts.clamp(1, 1024);
        self.max_parallel_name_resolutions = self.max_parallel_name_resolutions.clamp(1, 512);
        self
    }
}

impl Default for ScanSettings {
    fn default() -> Self {
        Self::approfondi()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_approfondi() {
        assert_eq!(ScanSettings::default(), ScanSettings::approfondi());
        let parsed: ScanSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(parsed, ScanSettings::approfondi());
    }

    #[test]
    fn round_trips_through_json() {
        for settings in [ScanSettings::rapide(), ScanSettings::approfondi()] {
            let json = serde_json::to_string(&settings).unwrap();
            assert_eq!(serde_json::from_str::<ScanSettings>(&json).unwrap(), settings);
        }
    }

    #[test]
    fn rapide_has_shorter_timeouts() {
        let (r, a) = (ScanSettings::rapide(), ScanSettings::approfondi());
        assert!(r.port_timeout_ms <= a.port_timeout_ms);
        assert!(r.name_timeout_ms <= a.name_timeout_ms);
        assert!(r.web_title_timeout_ms <= a.web_title_timeout_ms);
    }

    #[test]
    fn both_presets_keep_discovery_and_arp_sweep() {
        for s in [ScanSettings::rapide(), ScanSettings::approfondi()] {
            assert!(s.runs_active_discovery && s.runs_arp_sweep);
        }
    }

    #[test]
    fn preset_detection_and_application() {
        assert_eq!(ScanSettings::rapide().matching_preset(), Some(TimingPreset::Rapide));
        let mut custom = ScanSettings { max_tcp_connections: 100, ..ScanSettings::approfondi() };
        assert_eq!(custom.matching_preset(), Some(TimingPreset::Approfondi));
        custom.apply_preset(TimingPreset::Rapide);
        assert_eq!(custom.port_timeout_ms, 250);
        assert_eq!(custom.max_tcp_connections, 100);
        custom.port_timeout_ms = 333;
        assert_eq!(custom.matching_preset(), None);
    }

    #[test]
    fn sanitized_clamps_absurd_values() {
        let s =
            ScanSettings { max_tcp_connections: 0, max_parallel_hosts: 1_000_000, ..Default::default() }.sanitized();
        assert_eq!(s.max_tcp_connections, 1);
        assert_eq!(s.max_parallel_hosts, 1024);
    }
}
