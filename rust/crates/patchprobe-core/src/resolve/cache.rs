//! Cache de résolution par IP — port de `ResolutionCache.swift`, avec TTL et taille bornée.
//! Les échecs ne sont mémorisés que quelques minutes, jamais indéfiniment.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::types::TechniqueId;

pub const DEFAULT_MAX_ENTRIES: usize = 5000;
/// Un nom trouvé reste valable 7 jours.
pub const DEFAULT_SUCCESS_TTL_SECS: i64 = 7 * 24 * 3600;
/// Un échec n'est mémorisé que 5 minutes.
pub const DEFAULT_FAILURE_TTL_SECS: i64 = 5 * 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CacheEntry {
    pub hostname: Option<String>,
    pub technique: Option<TechniqueId>,
    /// Horodatage Unix (secondes).
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheLookup {
    Hit {
        name: String,
        technique: Option<TechniqueId>,
    },
    /// Échec récent (moins de [`DEFAULT_FAILURE_TTL_SECS`]) : inutile de relancer la chaîne lente.
    RecentFailure,
    Miss,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionCache {
    entries: HashMap<Ipv4Addr, CacheEntry>,
    #[serde(skip, default = "default_max")]
    max_entries: usize,
    #[serde(skip, default = "default_success_ttl")]
    success_ttl: i64,
    #[serde(skip, default = "default_failure_ttl")]
    failure_ttl: i64,
}

fn default_max() -> usize {
    DEFAULT_MAX_ENTRIES
}
fn default_success_ttl() -> i64 {
    DEFAULT_SUCCESS_TTL_SECS
}
fn default_failure_ttl() -> i64 {
    DEFAULT_FAILURE_TTL_SECS
}

impl Default for ResolutionCache {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_ENTRIES, DEFAULT_SUCCESS_TTL_SECS, DEFAULT_FAILURE_TTL_SECS)
    }
}

impl ResolutionCache {
    pub fn new(max_entries: usize, success_ttl: i64, failure_ttl: i64) -> Self {
        Self { entries: HashMap::new(), max_entries: max_entries.max(1), success_ttl, failure_ttl }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup(&self, ip: Ipv4Addr, now: i64) -> CacheLookup {
        let Some(entry) = self.entries.get(&ip) else { return CacheLookup::Miss };
        let age = now.saturating_sub(entry.updated_at);
        match &entry.hostname {
            Some(name) if age <= self.success_ttl => {
                CacheLookup::Hit { name: name.clone(), technique: entry.technique }
            }
            None if age <= self.failure_ttl => CacheLookup::RecentFailure,
            _ => CacheLookup::Miss,
        }
    }

    pub fn store_success(&mut self, ip: Ipv4Addr, name: &str, technique: TechniqueId, now: i64) {
        self.entries
            .insert(ip, CacheEntry { hostname: Some(name.to_owned()), technique: Some(technique), updated_at: now });
        self.evict(now);
    }

    /// Mémorise un échec court, sans écraser un nom encore valable (un hôte qui ne répond pas
    /// une fois garde son nom connu).
    pub fn store_failure(&mut self, ip: Ipv4Addr, now: i64) {
        if matches!(self.lookup(ip, now), CacheLookup::Hit { .. }) {
            return;
        }
        self.entries.insert(ip, CacheEntry { hostname: None, technique: None, updated_at: now });
        self.evict(now);
    }

    pub fn remove(&mut self, ip: Ipv4Addr) {
        self.entries.remove(&ip);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Supprime les entrées expirées, puis les plus anciennes au-delà de la taille maximale.
    pub fn evict(&mut self, now: i64) {
        let (success_ttl, failure_ttl) = (self.success_ttl, self.failure_ttl);
        self.entries.retain(|_, e| {
            let ttl = if e.hostname.is_some() { success_ttl } else { failure_ttl };
            now.saturating_sub(e.updated_at) <= ttl
        });
        if self.entries.len() > self.max_entries {
            let mut by_age: Vec<(Ipv4Addr, i64)> = self.entries.iter().map(|(ip, e)| (*ip, e.updated_at)).collect();
            by_age.sort_unstable_by_key(|(ip, at)| (*at, *ip));
            let excess = self.entries.len() - self.max_entries;
            for (ip, _) in by_age.into_iter().take(excess) {
                self.entries.remove(&ip);
            }
        }
    }

    /// Réapplique les limites après chargement depuis le disque.
    pub fn with_limits(mut self, max_entries: usize, now: i64) -> Self {
        self.max_entries = max_entries.max(1);
        self.evict(now);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    #[test]
    fn store_then_lookup_and_overwrite() {
        let mut cache = ResolutionCache::default();
        assert_eq!(cache.lookup(IP, 0), CacheLookup::Miss);
        cache.store_success(IP, "old-name.example.invalid", TechniqueId::Ptr, 0);
        cache.store_success(IP, "homeassistant.example.invalid", TechniqueId::Nbns, 10);
        assert_eq!(
            cache.lookup(IP, 20),
            CacheLookup::Hit { name: "homeassistant.example.invalid".into(), technique: Some(TechniqueId::Nbns) }
        );
        cache.clear();
        assert_eq!(cache.lookup(IP, 20), CacheLookup::Miss);
    }

    #[test]
    fn failures_expire_after_a_few_minutes() {
        let mut cache = ResolutionCache::default();
        cache.store_failure(IP, 1000);
        assert_eq!(cache.lookup(IP, 1000 + 60), CacheLookup::RecentFailure);
        assert_eq!(cache.lookup(IP, 1000 + DEFAULT_FAILURE_TTL_SECS + 1), CacheLookup::Miss);
    }

    #[test]
    fn successes_expire_after_ttl_and_are_not_erased_by_failure() {
        let mut cache = ResolutionCache::default();
        cache.store_success(IP, "nas", TechniqueId::Smb, 0);
        cache.store_failure(IP, 10);
        assert!(matches!(cache.lookup(IP, 10), CacheLookup::Hit { .. }));
        assert_eq!(cache.lookup(IP, DEFAULT_SUCCESS_TTL_SECS + 1), CacheLookup::Miss);
    }

    #[test]
    fn bounded_size_evicts_oldest() {
        let mut cache = ResolutionCache::new(3, 1000, 100);
        for i in 0..5u8 {
            cache.store_success(Ipv4Addr::new(198, 51, 100, i), "x", TechniqueId::Ptr, i64::from(i));
        }
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.lookup(Ipv4Addr::new(198, 51, 100, 0), 5), CacheLookup::Miss);
        assert!(matches!(cache.lookup(Ipv4Addr::new(198, 51, 100, 4), 5), CacheLookup::Hit { .. }));
    }

    #[test]
    fn serde_round_trip_keeps_entries() {
        let mut cache = ResolutionCache::default();
        cache.store_success(IP, "nas", TechniqueId::GatewayDns, 42);
        let json = serde_json::to_string(&cache).unwrap();
        let restored: ResolutionCache = serde_json::from_str(&json).unwrap();
        assert_eq!(
            restored.lookup(IP, 43),
            CacheLookup::Hit { name: "nas".into(), technique: Some(TechniqueId::GatewayDns) }
        );
    }
}
