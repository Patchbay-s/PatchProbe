//! Cœur de PatchProbe : logique pure et portable, sans dépendance d'interface ni d'OS.
//!
//! Les sorties texte des outils système (ping, arp, traceroute, nmap) sont parsées ici pour être
//! testables avec des fixtures ; leur exécution vit dans `patchprobe-platform`.

pub mod app_settings;
pub mod diff;
pub mod engine;
pub mod export;
pub mod iface;
pub mod model;
pub mod net;
pub mod oui;
pub mod parsers;
pub mod ports;
pub mod proto;
pub mod range;
pub mod resolve;
pub mod settings;
pub mod store;
pub mod ttl;

pub use model::{DeviceType, Host, HostStatus};
pub use ports::{parse_ports, resolve_ports, PortParseError, PortPresetKind, DEFAULT_TCP_PORTS};
pub use range::{InterfaceInfo, RangeError, ScanRange};
pub use settings::{ScanSettings, TimingPreset};
