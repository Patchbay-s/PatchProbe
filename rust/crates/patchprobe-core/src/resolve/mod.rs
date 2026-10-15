//! Résolution de nom multi-techniques avec trace typée par technique — port de la chaîne de
//! `ScanViewModel.scanHost/resolveFallbackHostname`.
//!
//! Différence volontaire avec la version Swift : les techniques directes (PTR, DNS du routeur,
//! mDNS, NBNS, SMB, LLMNR, SNMP) partent toutes en parallèle et chacune laisse son résultat dans
//! la trace, même quand une autre a déjà trouvé un nom. Le coût en temps est celui de la plus
//! lente (bornée par le timeout), et le panneau « Diagnostic du nom » voit exactement ce que
//! chaque étape a répondu.

pub mod cache;
pub mod discovery;
pub mod techniques;
pub mod types;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;

pub use cache::{CacheLookup, ResolutionCache};
pub use types::{
    ChosenName, NameResolution, NameTrace, NoNameResolution, Outcome, ResolveMode, TechniqueId, TechniqueResult,
};

use techniques::timed;

pub type SharedCache = Arc<Mutex<ResolutionCache>>;

/// Ports des protocoles (modifiables pour les tests sur loopback).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TechniquePorts {
    pub dns: u16,
    pub mdns: u16,
    pub nbns: u16,
    pub llmnr: u16,
    pub snmp: u16,
    pub smb: u16,
}

impl Default for TechniquePorts {
    fn default() -> Self {
        Self { dns: 53, mdns: 5353, nbns: 137, llmnr: 5355, snmp: 161, smb: 445 }
    }
}

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub name_timeout: Duration,
    pub web_title_timeout: Duration,
    pub discovery_budget: Duration,
    pub gateway: Option<Ipv4Addr>,
    pub snmp_community: String,
    pub ports: TechniquePorts,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            name_timeout: Duration::from_millis(1000),
            web_title_timeout: Duration::from_millis(1200),
            discovery_budget: Duration::from_millis(3000),
            gateway: None,
            snmp_community: "public".into(),
            ports: TechniquePorts::default(),
        }
    }
}

impl ResolverConfig {
    pub fn from_settings(settings: &crate::settings::ScanSettings, gateway: Option<Ipv4Addr>) -> Self {
        Self {
            name_timeout: Duration::from_millis(settings.name_timeout_ms),
            web_title_timeout: Duration::from_millis(settings.web_title_timeout_ms),
            gateway,
            ..Self::default()
        }
    }
}

pub struct Resolver {
    config: ResolverConfig,
    cache: SharedCache,
    http: Option<reqwest::Client>,
    clock: fn() -> i64,
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn skipped(technique: TechniqueId, reason: &str) -> TechniqueResult {
    TechniqueResult::new(technique, Outcome::Skipped(reason.to_owned()), Duration::ZERO)
}

/// Lance la technique, sauf si une raison de la sauter est fournie (la future n'est alors
/// jamais exécutée).
async fn unless_skipped<F>(technique: TechniqueId, skip: Option<&str>, future: F) -> TechniqueResult
where
    F: std::future::Future<Output = Outcome>,
{
    match skip {
        Some(reason) => skipped(technique, reason),
        None => timed(technique, future).await,
    }
}

impl Resolver {
    pub fn new(config: ResolverConfig, cache: SharedCache) -> Self {
        Self { config, cache, http: techniques::http_client(), clock: unix_now }
    }

    #[cfg(test)]
    fn with_clock(mut self, clock: fn() -> i64) -> Self {
        self.clock = clock;
        self
    }

    pub fn config(&self) -> &ResolverConfig {
        &self.config
    }

    fn cache_lookup(&self, ip: Ipv4Addr) -> CacheLookup {
        self.cache.lock().map(|c| c.lookup(ip, (self.clock)())).unwrap_or(CacheLookup::Miss)
    }

    async fn run(&self, ip: Ipv4Addr, open_ports: &[u16], mode: ResolveMode) -> NameTrace {
        let cfg = &self.config;
        let timeout = cfg.name_timeout;
        let cached = if mode == ResolveMode::Scan { self.cache_lookup(ip) } else { CacheLookup::Miss };
        // Comme la version Swift : PTR et DNS du routeur (peu coûteux) toujours rejoués ; la
        // chaîne lente est sautée si le cache a déjà un nom ou un échec très récent.
        let skip_reason = match &cached {
            CacheLookup::Hit { name, .. } => Some(format!("nom déjà en cache : {name}")),
            CacheLookup::RecentFailure => Some("échec récent mémorisé (moins de 5 min)".to_owned()),
            CacheLookup::Miss => None,
        };
        let skip = skip_reason.as_deref();
        let at = |port: u16| SocketAddrV4::new(ip, port);
        let (ptr, gateway, mdns, nbns, smb, llmnr, snmp) = tokio::join!(
            timed(TechniqueId::Ptr, techniques::system_ptr(ip, timeout)),
            timed(TechniqueId::GatewayDns, techniques::gateway_dns(ip, cfg.gateway, cfg.ports.dns, timeout)),
            unless_skipped(
                TechniqueId::Mdns,
                skip,
                techniques::dns_ptr(at(cfg.ports.mdns), ip, timeout, false, "mDNS")
            ),
            unless_skipped(TechniqueId::Nbns, skip, techniques::nbns_query(at(cfg.ports.nbns), timeout)),
            unless_skipped(TechniqueId::Smb, skip, techniques::smb_name(at(cfg.ports.smb), timeout)),
            unless_skipped(
                TechniqueId::Llmnr,
                skip,
                techniques::dns_ptr(at(cfg.ports.llmnr), ip, timeout, false, "LLMNR")
            ),
            unless_skipped(
                TechniqueId::Snmp,
                skip,
                techniques::snmp_sys_name(at(cfg.ports.snmp), &cfg.snmp_community, timeout)
            ),
        );
        let mut trace = NameTrace::new(ip);
        for result in [ptr, gateway, mdns, nbns, smb, llmnr, snmp] {
            trace.push(result);
        }

        let has_name = trace.results.iter().any(|r| r.outcome.found().is_some());
        let web = if let (ResolveMode::Scan, Some(reason)) = (mode, skip_reason.as_deref()) {
            skipped(TechniqueId::WebTitle, reason)
        } else if mode == ResolveMode::Scan && has_name {
            skipped(TechniqueId::WebTitle, "un nom a déjà été trouvé")
        } else {
            timed(
                TechniqueId::WebTitle,
                techniques::web_title(self.http.as_ref(), ip, open_ports, cfg.web_title_timeout),
            )
            .await
        };
        trace.push(web);

        if let CacheLookup::Hit { name, .. } = &cached {
            trace.push(TechniqueResult::new(TechniqueId::Cache, Outcome::Found(name.clone()), Duration::ZERO));
        }
        trace.choose();
        self.remember(&trace, mode);
        trace
    }

    fn remember(&self, trace: &NameTrace, mode: ResolveMode) {
        let Ok(mut cache) = self.cache.lock() else { return };
        let now = (self.clock)();
        match &trace.chosen {
            Some(chosen) if chosen.technique != TechniqueId::Cache => {
                cache.store_success(trace.ip, &chosen.name, chosen.technique, now);
            }
            Some(_) => {}
            None if mode == ResolveMode::Scan => cache.store_failure(trace.ip, now),
            None => {}
        }
    }

    /// Mémorise un nom découvert en fin de scan (Bonjour/SSDP).
    pub fn remember_discovered(&self, ip: Ipv4Addr, name: &str, technique: TechniqueId) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.store_success(ip, name, technique, (self.clock)());
        }
    }
}

#[async_trait]
impl NameResolution for Resolver {
    async fn resolve(&self, ip: Ipv4Addr, open_ports: &[u16], mode: ResolveMode) -> NameTrace {
        self.run(ip, open_ports, mode).await
    }

    async fn discover(&self) -> HashMap<Ipv4Addr, (String, TechniqueId)> {
        let budget = self.config.discovery_budget;
        let (bonjour, ssdp) = tokio::join!(discovery::bonjour(budget), discovery::ssdp(budget, self.http.as_ref()));
        let mut found: HashMap<Ipv4Addr, (String, TechniqueId)> =
            ssdp.into_iter().map(|(ip, name)| (ip, (name, TechniqueId::Ssdp))).collect();
        // Bonjour prioritaire (même ordre que la version Swift).
        found.extend(bonjour.into_iter().map(|(ip, name)| (ip, (name, TechniqueId::Bonjour))));
        for (ip, (name, technique)) in &found {
            self.remember_discovered(*ip, name, *technique);
        }
        found
    }
}

#[cfg(test)]
mod tests;
