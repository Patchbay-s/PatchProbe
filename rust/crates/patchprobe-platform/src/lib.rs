//! Couche dépendante de l'OS : sous-processus (ping, arp, nmap, traceroute…), interfaces,
//! passerelle, navigateur, dossier de données. Les parseurs de sortie vivent dans
//! `patchprobe-core::parsers` et sont testés avec des fixtures des trois OS.

pub mod paths;
pub mod process;
pub mod system;
pub mod tools;

pub use patchprobe_core as core;

/// Vrai dans le bac à sable d'Apple (édition Mac App Store) : la table ARP y est vide et
/// traceroute ou nmap ne peuvent pas être lancés.
pub fn is_sandboxed() -> bool {
    cfg!(target_os = "macos") && std::env::var_os("APP_SANDBOX_CONTAINER_ID").is_some()
}
pub use system::{validate_url, Ipv4Config, NetworkProfile, Platform, PlatformError, SystemPlatform};
