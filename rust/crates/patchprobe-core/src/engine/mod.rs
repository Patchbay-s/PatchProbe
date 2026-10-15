//! Moteur de scan — port de `ScanViewModel.startScan/scanHost/mergeArpTable/merge*Names`.
//!
//! - ping et scan TCP en parallèle par hôte ; un port ouvert prouve la présence ;
//! - plafond GLOBAL de connexions TCP (un seul sémaphore pour tous hôtes et ports) + plafond
//!   d'hôtes en parallèle ;
//! - résolution de nom dans des tâches séparées, sous son propre budget (jamais affamée par le
//!   scan de ports, qui libère la place de l'hôte dès la sonde finie) ;
//! - annulation par `CancellationToken` : toutes les tâches, sockets et processus enfants sont
//!   abandonnés (les `JoinSet` sont détruits) ;
//! - résultats émis en streaming sur un canal `mpsc`, avec la progression.

pub mod limits;
pub mod ports;

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde::Serialize;
use tokio::sync::{mpsc, Semaphore};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::model::{Host, HostStatus};
use crate::net::tcp::TcpConnector;
use crate::oui;
use crate::range::ScanRange;
use crate::resolve::types::{NameResolution, NameTrace, ResolveMode, TechniqueId};
use crate::settings::ScanSettings;
use limits::ConnectionLimiter;
use ports::PortScanStats;

/// Réponse d'un ping système.
#[derive(Debug, Clone, Copy, PartialEq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PingReply {
    pub alive: bool,
    pub latency_ms: Option<f64>,
    pub ttl: Option<u8>,
}

/// Opérations système dont le moteur a besoin (implémentées par `patchprobe-platform`).
#[async_trait]
pub trait SystemProbe: Send + Sync + 'static {
    async fn ping(&self, ip: Ipv4Addr, timeout: Duration) -> PingReply;
    /// MAC d'un hôte dans le cache ARP/voisins, juste après l'avoir contacté.
    async fn arp_lookup(&self, ip: Ipv4Addr) -> Option<String>;
    /// Table ARP/voisins complète (entrées incomplètes exclues).
    async fn arp_table(&self) -> HashMap<Ipv4Addr, String>;
}

/// Fabricant par MAC : correction manuelle d'abord, sinon base OUI.
#[derive(Debug, Clone, Default)]
pub struct VendorLookup {
    overrides: HashMap<String, String>,
}

impl VendorLookup {
    /// `overrides` : MAC (toute forme) → fabricant ; les clés sont normalisées.
    pub fn new(overrides: &HashMap<String, String>) -> Self {
        let overrides = overrides
            .iter()
            .map(|(mac, vendor)| (oui::normalize_mac(mac).unwrap_or_else(|| mac.to_lowercase()), vendor.clone()))
            .collect();
        Self { overrides }
    }

    /// (fabricant, corrigé manuellement ?)
    pub fn vendor(&self, mac: &str) -> (Option<String>, bool) {
        let key = oui::normalize_mac(mac).unwrap_or_else(|| mac.to_lowercase());
        match self.overrides.get(&key) {
            Some(custom) => (Some(custom.clone()), true),
            None => (oui::vendor(mac).map(str::to_owned), false),
        }
    }
}

pub struct ScanRequest {
    pub scan_id: u64,
    pub range: ScanRange,
    pub ports: Vec<u16>,
    pub settings: ScanSettings,
    pub vendors: VendorLookup,
}

pub struct ScanDeps {
    pub system: Arc<dyn SystemProbe>,
    pub names: Arc<dyn NameResolution>,
    pub connector: Arc<dyn TcpConnector>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ScanPhase {
    Hosts,
    ArpSweep,
    Discovery,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStats {
    pub duration_ms: u64,
    pub peak_tcp_connections: usize,
    pub resource_exhaustion_events: u64,
    pub abandoned_probes: u64,
}

/// Événements streamés vers l'interface.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ScanEvent {
    #[serde(rename_all = "camelCase")]
    Started { scan_id: u64, total: u64, port_count: usize },
    #[serde(rename_all = "camelCase")]
    Phase { scan_id: u64, phase: ScanPhase },
    #[serde(rename_all = "camelCase")]
    Host { scan_id: u64, host: Host },
    #[serde(rename_all = "camelCase")]
    NameTrace { scan_id: u64, trace: NameTrace },
    #[serde(rename_all = "camelCase")]
    Progress { scan_id: u64, scanned: u64, total: u64, up: u64 },
    #[serde(rename_all = "camelCase")]
    Warning { scan_id: u64, message: String },
    #[serde(rename_all = "camelCase")]
    Finished { scan_id: u64, cancelled: bool, up: u64, total: u64, stats: ScanStats },
}

pub struct ScanOutcome {
    pub hosts: Vec<Host>,
    pub traces: HashMap<Ipv4Addr, NameTrace>,
    pub cancelled: bool,
    pub stats: ScanStats,
}

pub const NO_HOST_WARNING: &str = "Aucun hôte actif trouvé. Si ce résultat vous surprend : vérifiez que \
vous êtes sur le bon réseau (VPN ?), que le pare-feu autorise PatchProbe, et sous macOS que l'accès \
« Réseau local » est autorisé (Réglages Système > Confidentialité et sécurité > Réseau local).";

pub const EXHAUSTION_WARNING: &str = "Le système a manqué de ressources réseau (descripteurs ou \
tampons) : le scan a ralenti automatiquement. Réduisez le plafond de connexions TCP dans les réglages.";

/// Résultat de la sonde d'un hôte (ping + ports + ARP ciblé).
struct HostProbe {
    ip: Ipv4Addr,
    ping: PingReply,
    open_ports: Vec<u16>,
    mac: Option<String>,
}

#[derive(Clone)]
struct Ctx {
    system: Arc<dyn SystemProbe>,
    names: Arc<dyn NameResolution>,
    connector: Arc<dyn TcpConnector>,
    limiter: Arc<ConnectionLimiter>,
    name_budget: Arc<Semaphore>,
    port_stats: Arc<PortScanStats>,
    ports: Arc<[u16]>,
    settings: ScanSettings,
}

async fn probe_host(ctx: Ctx, ip: Ipv4Addr) -> HostProbe {
    let ping_timeout = Duration::from_millis(ctx.settings.ping_timeout_ms);
    let port_timeout = Duration::from_millis(ctx.settings.port_timeout_ms);
    let (ping, open_ports) = tokio::join!(
        ctx.system.ping(ip, ping_timeout),
        ports::scan_ports(ip, &ctx.ports, port_timeout, &ctx.limiter, &ctx.connector, &ctx.port_stats),
    );
    let alive = ping.alive || !open_ports.is_empty();
    // MAC lue tout de suite, pendant que l'entrée ARP est fraîche.
    let mac = if alive { ctx.system.arp_lookup(ip).await } else { None };
    HostProbe { ip, ping, open_ports, mac }
}

async fn resolve_name(ctx: Ctx, ip: Ipv4Addr, open_ports: Vec<u16>) -> NameTrace {
    // Budget propre à la résolution : indépendant du plafond TCP du scan de ports.
    let _permit = ctx.name_budget.acquire_owned().await.ok();
    ctx.names.resolve(ip, &open_ports, ResolveMode::Scan).await
}

struct ScanState {
    scan_id: u64,
    range: ScanRange,
    hosts: Vec<Host>,
    traces: HashMap<Ipv4Addr, NameTrace>,
    scanned: u64,
    vendors: VendorLookup,
    events: mpsc::Sender<ScanEvent>,
}

impl ScanState {
    fn index(&self, ip: Ipv4Addr) -> Option<usize> {
        if !self.range.contains(ip) {
            return None;
        }
        usize::try_from(u32::from(ip) - u32::from(self.range.first())).ok()
    }

    fn up_count(&self) -> u64 {
        u64::try_from(self.hosts.iter().filter(|h| h.status == HostStatus::Up).count()).unwrap_or(u64::MAX)
    }

    async fn emit(&self, event: ScanEvent) {
        // Interface fermée : on continue silencieusement (l'annulation arrive par le jeton).
        let _ = self.events.send(event).await;
    }

    async fn emit_host(&self, index: usize) {
        if let Some(host) = self.hosts.get(index) {
            self.emit(ScanEvent::Host { scan_id: self.scan_id, host: host.clone() }).await;
        }
    }

    async fn emit_progress(&self) {
        self.emit(ScanEvent::Progress {
            scan_id: self.scan_id,
            scanned: self.scanned,
            total: self.range.len(),
            up: self.up_count(),
        })
        .await;
    }

    fn set_mac(&mut self, index: usize, mac: &str) {
        let (vendor, overridden) = self.vendors.vendor(mac);
        if let Some(host) = self.hosts.get_mut(index) {
            host.mac = Some(oui::normalize_mac(mac).unwrap_or_else(|| mac.to_owned()));
            host.vendor = vendor;
            host.vendor_overridden = overridden;
            host.refresh_derived();
        }
    }

    /// Applique une sonde ; renvoie l'index si l'hôte est vivant.
    fn apply_probe(&mut self, probe: HostProbe) -> Option<usize> {
        let index = self.index(probe.ip)?;
        let alive = probe.ping.alive || !probe.open_ports.is_empty();
        let host = self.hosts.get_mut(index)?;
        if !alive {
            host.status = HostStatus::Down;
            return None;
        }
        host.status = HostStatus::Up;
        host.latency_ms = probe.ping.latency_ms;
        host.open_ports = probe.open_ports;
        if probe.ping.alive {
            host.apply_ttl(probe.ping.ttl);
        }
        host.refresh_derived();
        if let Some(mac) = probe.mac {
            self.set_mac(index, &mac);
        }
        Some(index)
    }

    fn apply_trace(&mut self, trace: NameTrace) -> Option<usize> {
        let index = self.index(trace.ip)?;
        if let (Some(host), Some(chosen)) = (self.hosts.get_mut(index), trace.chosen.as_ref()) {
            host.hostname = Some(chosen.name.clone());
            host.hostname_source = Some(chosen.technique.as_str().to_owned());
            host.refresh_derived();
        }
        self.traces.insert(trace.ip, trace);
        Some(index)
    }

    async fn handle_trace(&mut self, trace: NameTrace) {
        let named = trace.chosen.is_some();
        let event = ScanEvent::NameTrace { scan_id: self.scan_id, trace: trace.clone() };
        if let Some(index) = self.apply_trace(trace) {
            self.emit(event).await;
            if named {
                self.emit_host(index).await;
            }
        }
    }

    /// Phase 1 : sonde de tous les hôtes + résolution de nom des vivants.
    async fn run_hosts(&mut self, ctx: &Ctx) {
        let max_hosts = ctx.settings.max_parallel_hosts.max(1);
        let mut probes: JoinSet<HostProbe> = JoinSet::new();
        let mut names: JoinSet<NameTrace> = JoinSet::new();
        let mut ips = self.range.iter();
        loop {
            while probes.len() < max_hosts {
                match ips.next() {
                    Some(ip) => {
                        probes.spawn(probe_host(ctx.clone(), ip));
                    }
                    None => break,
                }
            }
            if probes.is_empty() && names.is_empty() {
                break;
            }
            tokio::select! {
                Some(result) = probes.join_next(), if !probes.is_empty() => {
                    let Ok(probe) = result else { continue };
                    let ip = probe.ip;
                    let ports = probe.open_ports.clone();
                    let alive_index = self.apply_probe(probe);
                    self.scanned += 1;
                    if let Some(index) = alive_index {
                        names.spawn(resolve_name(ctx.clone(), ip, ports));
                        self.emit_host(index).await;
                    } else if let Some(index) = self.index(ip) {
                        self.emit_host(index).await;
                    }
                    self.emit_progress().await;
                }
                Some(result) = names.join_next(), if !names.is_empty() => {
                    if let Ok(trace) = result {
                        self.handle_trace(trace).await;
                    }
                }
            }
        }
    }

    /// Fusionne la table ARP : MAC des vivants, et promotion « inactif → actif » (ARP est la
    /// preuve la plus forte qu'un appareil occupe l'IP). Renvoie les IP promues.
    async fn merge_arp(&mut self, ctx: &Ctx) -> Vec<Ipv4Addr> {
        let table = ctx.system.arp_table().await;
        let mut promoted = Vec::new();
        let mut entries: Vec<(Ipv4Addr, String)> = table.into_iter().collect();
        entries.sort_unstable();
        for (ip, mac) in entries {
            let Some(index) = self.index(ip) else { continue };
            let Some(host) = self.hosts.get_mut(index) else { continue };
            if host.status == HostStatus::Down {
                host.status = HostStatus::Up;
                promoted.push(ip);
            }
            if host.status != HostStatus::Up {
                continue;
            }
            let changed = host.mac.as_deref() != oui::normalize_mac(&mac).as_deref();
            if changed {
                self.set_mac(index, &mac);
                self.emit_host(index).await;
            } else if promoted.last() == Some(&ip) {
                self.emit_host(index).await;
            }
        }
        promoted
    }

    async fn resolve_many(&mut self, ctx: &Ctx, ips: Vec<Ipv4Addr>) {
        let mut names: JoinSet<NameTrace> = JoinSet::new();
        for ip in ips {
            let ports =
                self.index(ip).and_then(|i| self.hosts.get(i)).map(|h| h.open_ports.clone()).unwrap_or_default();
            names.spawn(resolve_name(ctx.clone(), ip, ports));
        }
        while let Some(result) = names.join_next().await {
            if let Ok(trace) = result {
                self.handle_trace(trace).await;
            }
        }
    }

    /// Phase 2 : balayage ARP de fin de scan en deux passes.
    async fn run_arp_sweep(&mut self, ctx: &Ctx) {
        let promoted = self.merge_arp(ctx).await;
        if !promoted.is_empty() {
            self.emit_progress().await;
            self.resolve_many(ctx, promoted).await;
        }
        if !ctx.settings.runs_arp_sweep {
            return;
        }
        // Les hôtes routés n'auront jamais de MAC par ARP : inutile de les re-pinger.
        let missing: Vec<Ipv4Addr> = self
            .hosts
            .iter()
            .filter(|h| h.status == HostStatus::Up && h.mac.is_none() && !h.is_likely_routed)
            .map(|h| h.ip)
            .collect();
        if missing.is_empty() {
            return;
        }
        let timeout = Duration::from_millis(ctx.settings.ping_timeout_ms);
        let max_hosts = ctx.settings.max_parallel_hosts.max(1);
        let mut pings = JoinSet::new();
        let mut pending = missing.into_iter();
        loop {
            while pings.len() < max_hosts {
                let Some(ip) = pending.next() else { break };
                let system = Arc::clone(&ctx.system);
                pings.spawn(async move { system.ping(ip, timeout).await });
            }
            if pings.join_next().await.is_none() {
                break;
            }
        }
        let promoted = self.merge_arp(ctx).await;
        if !promoted.is_empty() {
            self.emit_progress().await;
            self.resolve_many(ctx, promoted).await;
        }
    }

    /// Phase 3 : Bonjour/SSDP pour les hôtes vivants encore sans nom.
    async fn run_discovery(&mut self, ctx: &Ctx) {
        let needs_name = self.hosts.iter().any(|h| h.status == HostStatus::Up && h.hostname.is_none());
        if !needs_name {
            return;
        }
        let discovered = ctx.names.discover().await;
        let mut found: Vec<(Ipv4Addr, String, TechniqueId)> =
            discovered.into_iter().map(|(ip, (name, technique))| (ip, name, technique)).collect();
        found.sort_unstable_by_key(|(ip, _, _)| *ip);
        for (ip, name, technique) in found {
            let Some(index) = self.index(ip) else { continue };
            let eligible = self.hosts.get(index).is_some_and(|h| h.status == HostStatus::Up && h.hostname.is_none());
            if !eligible {
                continue;
            }
            let mut trace = self.traces.remove(&ip).unwrap_or_else(|| NameTrace::new(ip));
            trace.set_discovered(technique, name);
            self.handle_trace(trace).await;
        }
    }

    async fn run_all(&mut self, ctx: &Ctx) {
        self.emit(ScanEvent::Phase { scan_id: self.scan_id, phase: ScanPhase::Hosts }).await;
        self.run_hosts(ctx).await;
        self.emit(ScanEvent::Phase { scan_id: self.scan_id, phase: ScanPhase::ArpSweep }).await;
        self.run_arp_sweep(ctx).await;
        if ctx.settings.runs_active_discovery {
            self.emit(ScanEvent::Phase { scan_id: self.scan_id, phase: ScanPhase::Discovery }).await;
            self.run_discovery(ctx).await;
        }
    }
}

/// Lance un scan complet. Retourne quand le scan est fini ou annulé ; dans les deux cas un
/// événement `Finished` est émis et les hôtes connus sont renvoyés.
pub async fn run_scan(
    request: ScanRequest,
    deps: ScanDeps,
    events: mpsc::Sender<ScanEvent>,
    cancel: CancellationToken,
) -> ScanOutcome {
    let started = Instant::now();
    let settings = request.settings.clone().sanitized();
    let ctx = Ctx {
        system: deps.system,
        names: deps.names,
        connector: deps.connector,
        limiter: ConnectionLimiter::new(settings.max_tcp_connections),
        name_budget: Arc::new(Semaphore::new(settings.max_parallel_name_resolutions.max(1))),
        port_stats: Arc::new(PortScanStats::default()),
        ports: Arc::from(request.ports.as_slice()),
        settings,
    };
    let mut state = ScanState {
        scan_id: request.scan_id,
        range: request.range,
        hosts: request.range.iter().map(Host::new).collect(),
        traces: HashMap::new(),
        scanned: 0,
        vendors: request.vendors,
        events,
    };
    state
        .emit(ScanEvent::Started { scan_id: state.scan_id, total: state.range.len(), port_count: ctx.ports.len() })
        .await;

    let cancelled = cancel.run_until_cancelled(state.run_all(&ctx)).await.is_none();

    let stats = ScanStats {
        duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        peak_tcp_connections: ctx.limiter.peak(),
        resource_exhaustion_events: ctx.port_stats.exhaustion_events(),
        abandoned_probes: ctx.port_stats.abandoned_probes(),
    };
    let up = state.up_count();
    if !cancelled {
        if state.range.len() > 1 && up == 0 {
            state.emit(ScanEvent::Warning { scan_id: state.scan_id, message: NO_HOST_WARNING.to_owned() }).await;
        }
        if stats.resource_exhaustion_events > 0 {
            state.emit(ScanEvent::Warning { scan_id: state.scan_id, message: EXHAUSTION_WARNING.to_owned() }).await;
        }
    }
    state
        .emit(ScanEvent::Finished {
            scan_id: state.scan_id,
            cancelled,
            up,
            total: state.range.len(),
            stats: stats.clone(),
        })
        .await;
    ScanOutcome { hosts: state.hosts, traces: state.traces, cancelled, stats }
}

#[cfg(test)]
mod tests;
