//! État partagé de l'application.

use std::collections::{BTreeMap, HashMap};
use std::net::Ipv4Addr;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use patchprobe_core::app_settings::AppSettings;
use patchprobe_core::model::{Annotations, Host, HostStatus, SiteProfile, VendorOverrides};
use patchprobe_core::resolve::{NameTrace, ResolutionCache};
use patchprobe_core::store::{DataPaths, HistoryStore, Store, DEFAULT_DEBOUNCE};
use patchprobe_platform::SystemPlatform;
use tokio_util::sync::CancellationToken;

/// Résultats affichés : scan en cours, terminé ou rechargé depuis l'historique.
#[derive(Default)]
pub struct CurrentScan {
    pub scan_id: u64,
    pub range_input: String,
    pub hosts: BTreeMap<Ipv4Addr, Host>,
    pub traces: HashMap<Ipv4Addr, NameTrace>,
}

impl CurrentScan {
    pub fn hosts_vec(&self) -> Vec<Host> {
        self.hosts.values().cloned().collect()
    }

    pub fn live_hosts(&self) -> Vec<Host> {
        self.hosts.values().filter(|h| h.status == HostStatus::Up).cloned().collect()
    }
}

fn open_store<T>(path: &std::path::Path, label: &str, warnings: &mut Vec<String>) -> Store<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Default + Clone + Send + 'static,
{
    let (store, status) = Store::open(path, DEFAULT_DEBOUNCE);
    warnings.extend(status.warning(label));
    store
}

pub struct AppState {
    pub platform: Arc<SystemPlatform>,
    pub paths: DataPaths,
    pub settings: Store<AppSettings>,
    pub annotations: Store<Annotations>,
    pub site_profiles: Store<Vec<SiteProfile>>,
    pub vendor_overrides: Store<VendorOverrides>,
    pub resolution_cache: Store<ResolutionCache>,
    pub history: HistoryStore,
    pub current: Mutex<CurrentScan>,
    /// Jeton du scan en cours : un nouveau scan ou la fermeture l'annule.
    pub scan_cancel: Mutex<Option<CancellationToken>>,
    pub scan_counter: AtomicU64,
    /// Outils en cours par clé (`nmap:192.0.2.10`…), annulables.
    pub tools: Mutex<HashMap<String, (u64, CancellationToken)>>,
    pub tool_counter: AtomicU64,
    /// Avertissements de chargement (fichiers mis de côté…).
    pub load_warnings: Vec<String>,
}

impl AppState {
    /// Doit être appelé dans le runtime tokio (les stores démarrent leur écrivain débouncé).
    pub fn load(paths: DataPaths) -> Self {
        let mut warnings = Vec::new();
        let settings: Store<AppSettings> = open_store(&paths.settings(), "Réglages", &mut warnings);
        settings.update(|s| *s = s.clone().sanitized());
        let annotations = open_store(&paths.annotations(), "Favoris et notes", &mut warnings);
        let site_profiles = open_store(&paths.site_profiles(), "Profils de site", &mut warnings);
        let vendor_overrides = open_store(&paths.vendor_overrides(), "Corrections de fabricant", &mut warnings);
        let resolution_cache = open_store(&paths.resolution_cache(), "Cache de résolution", &mut warnings);
        let history = HistoryStore::new(paths.history_dir());
        Self {
            platform: Arc::new(SystemPlatform::new()),
            paths,
            settings,
            annotations,
            site_profiles,
            vendor_overrides,
            resolution_cache,
            history,
            current: Mutex::new(CurrentScan::default()),
            scan_cancel: Mutex::new(None),
            scan_counter: AtomicU64::new(0),
            tools: Mutex::new(HashMap::new()),
            tool_counter: AtomicU64::new(0),
            load_warnings: warnings,
        }
    }

    /// Annule le scan et tous les outils en cours (nouveau scan, fermeture).
    pub fn cancel_all(&self) {
        if let Ok(mut slot) = self.scan_cancel.lock() {
            if let Some(token) = slot.take() {
                token.cancel();
            }
        }
        if let Ok(mut tools) = self.tools.lock() {
            for (_, (_, token)) in tools.drain() {
                token.cancel();
            }
        }
    }

    pub async fn flush_all(&self) {
        self.settings.flush().await;
        self.annotations.flush().await;
        self.site_profiles.flush().await;
        self.vendor_overrides.flush().await;
        self.resolution_cache.flush().await;
    }

    pub fn with_current<R>(&self, f: impl FnOnce(&mut CurrentScan) -> R) -> Result<R, String> {
        self.current.lock().map(|mut c| f(&mut c)).map_err(|_| "état interne indisponible".to_owned())
    }

    /// Enregistre un outil annulable ; un outil déjà lancé avec la même clé est annulé.
    pub fn start_tool(&self, key: &str) -> (u64, CancellationToken) {
        let id = self.tool_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let token = CancellationToken::new();
        if let Ok(mut tools) = self.tools.lock() {
            if let Some((_, previous)) = tools.insert(key.to_owned(), (id, token.clone())) {
                previous.cancel();
            }
        }
        (id, token)
    }

    pub fn finish_tool(&self, key: &str, id: u64) {
        if let Ok(mut tools) = self.tools.lock() {
            if tools.get(key).is_some_and(|(current, _)| *current == id) {
                tools.remove(key);
            }
        }
    }

    pub fn cancel_tool(&self, key: &str) {
        if let Ok(mut tools) = self.tools.lock() {
            if let Some((_, token)) = tools.remove(key) {
                token.cancel();
            }
        }
    }
}
