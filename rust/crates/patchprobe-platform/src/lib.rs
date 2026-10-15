//! Couche dépendante de l'OS : sous-processus (ping, arp, nmap, traceroute…), interfaces,
//! passerelle, navigateur, dossier de données. Les parseurs de sortie vivent dans
//! `patchprobe-core::parsers` et sont testés avec des fixtures des trois OS.

pub mod paths;
pub mod process;
pub mod system;
pub mod tools;

pub use patchprobe_core as core;
pub use system::{validate_url, Ipv4Config, NetworkProfile, Platform, PlatformError, SystemPlatform};
