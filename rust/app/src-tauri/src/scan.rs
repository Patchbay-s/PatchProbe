//! Lancement d'un scan et transfert des événements vers l'interface.
//!
//! Les mises à jour d'hôtes sont regroupées (au plus une émission toutes les 120 ms, une
//! entrée par IP) : un /16 produit 65 536 résultats, l'interface ne doit pas recevoir 65 536
//! messages.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use patchprobe_core::engine::{run_scan, ScanDeps, ScanEvent, ScanRequest, SystemProbe, VendorLookup};
use patchprobe_core::model::{Host, ScanSnapshot};
use patchprobe_core::net::tcp::TokioConnector;
use patchprobe_core::range::ScanRange;
use patchprobe_core::resolve::{Resolver, ResolverConfig};
use patchprobe_core::resolve_ports;
use patchprobe_platform::Platform;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::state::{AppState, CurrentScan};

pub const EVENT_HOSTS: &str = "scan://hosts";
pub const EVENT_SCAN: &str = "scan://event";
pub const EVENT_COMPLETED: &str = "scan://completed";

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostsBatch {
    pub scan_id: u64,
    pub hosts: Vec<Host>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCompleted {
    pub scan_id: u64,
    pub cancelled: bool,
    pub up: usize,
    pub history_saved: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanStarted {
    pub scan_id: u64,
    pub total: u64,
    pub port_count: usize,
}

pub fn emit_hosts(app: &AppHandle, scan_id: u64, hosts: Vec<Host>) {
    if !hosts.is_empty() {
        let _ = app.emit(EVENT_HOSTS, HostsBatch { scan_id, hosts });
    }
}

/// Valide la saisie, annule le scan précédent et lance le nouveau en tâche de fond.
pub fn start(app: &AppHandle, state: &AppState, range_input: &str, ports_input: &str) -> Result<ScanStarted, String> {
    let range = ScanRange::parse(range_input).map_err(|e| e.to_string())?;
    let ports = resolve_ports(ports_input).map_err(|e| format!("Ports : {e}"))?;
    state.settings.update(|s| {
        s.remember_recent_range(range_input);
        s.ports_input = ports_input.trim().to_owned();
    });
    let settings = state.settings.get().scan;

    state.cancel_all();
    let cancel = CancellationToken::new();
    if let Ok(mut slot) = state.scan_cancel.lock() {
        *slot = Some(cancel.clone());
    }
    let scan_id = state.scan_counter.fetch_add(1, Ordering::SeqCst) + 1;
    state.with_current(|current| {
        *current = CurrentScan { scan_id, range_input: range_input.trim().to_owned(), ..CurrentScan::default() };
    })?;

    let vendors = VendorLookup::new(&state.vendor_overrides.get().as_map());
    let started = ScanStarted { scan_id, total: range.len(), port_count: ports.len() };
    let request = ScanRequest { scan_id, range, ports, settings: settings.clone(), vendors };
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let platform = Arc::clone(&state.platform);
        let interface = platform.active_interface().await;
        let gateway = platform.default_gateway(interface.as_ref()).await;
        let resolver =
            Resolver::new(ResolverConfig::from_settings(&settings, gateway), state.resolution_cache.shared());
        let deps = ScanDeps {
            system: platform as Arc<dyn SystemProbe>,
            names: Arc::new(resolver),
            connector: Arc::new(TokioConnector),
        };
        let (tx, rx) = mpsc::channel(4096);
        let forwarder = tauri::async_runtime::spawn(forward(app.clone(), scan_id, rx));
        let outcome = run_scan(request, deps, tx, cancel).await;
        let _ = forwarder.await;
        state.resolution_cache.touch();

        // Un scan plus récent a pris la main : ses résultats ne doivent pas être écrasés.
        let still_current = state.with_current(|c| c.scan_id == scan_id).unwrap_or(false);
        let up = outcome.hosts.iter().filter(|h| h.status == patchprobe_core::HostStatus::Up).count();
        let mut completed =
            ScanCompleted { scan_id, cancelled: outcome.cancelled, up, history_saved: false, error: None };
        if still_current {
            let range_input = state.with_current(|c| c.range_input.clone()).unwrap_or_default();
            let _ = state.with_current(|current| {
                current.hosts = outcome.hosts.iter().map(|h| (h.ip, h.clone())).collect();
                current.traces = outcome.traces.clone();
            });
            if !outcome.cancelled {
                match ScanSnapshot::from_scan(&range_input, &outcome.hosts, chrono::Utc::now()) {
                    Some(snapshot) => match state.history.save(&snapshot) {
                        Ok(()) => completed.history_saved = true,
                        Err(e) => {
                            completed.error = Some(format!(
                                "Résultats trouvés, mais l'enregistrement dans l'historique a échoué ({e}). Vérifiez l'espace disque disponible."
                            ));
                        }
                    },
                    None => completed.history_saved = false,
                }
            }
        }
        let _ = app.emit(EVENT_COMPLETED, completed);
    });
    Ok(started)
}

/// Relaie les événements du moteur : hôtes regroupés, progression fusionnée, traces gardées
/// dans l'état (consultées à la demande par le panneau de diagnostic).
async fn forward(app: AppHandle, scan_id: u64, mut rx: mpsc::Receiver<ScanEvent>) {
    let state = app.state::<AppState>();
    let mut pending: HashMap<Ipv4Addr, Host> = HashMap::new();
    let mut progress: Option<ScanEvent> = None;
    let mut ticker = tokio::time::interval(Duration::from_millis(120));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let flush = |pending: &mut HashMap<Ipv4Addr, Host>, progress: &mut Option<ScanEvent>| {
        if !pending.is_empty() {
            let mut hosts: Vec<Host> = pending.drain().map(|(_, h)| h).collect();
            hosts.sort_by_key(|h| h.ip);
            let _ = state.with_current(|current| {
                if current.scan_id == scan_id {
                    for host in &hosts {
                        current.hosts.insert(host.ip, host.clone());
                    }
                }
            });
            emit_hosts(&app, scan_id, hosts);
        }
        if let Some(event) = progress.take() {
            let _ = app.emit(EVENT_SCAN, event);
        }
    };

    loop {
        tokio::select! {
            event = rx.recv() => match event {
                None => {
                    flush(&mut pending, &mut progress);
                    break;
                }
                Some(ScanEvent::Host { host, .. }) => {
                    pending.insert(host.ip, host);
                }
                Some(event @ ScanEvent::Progress { .. }) => progress = Some(event),
                Some(ScanEvent::NameTrace { trace, .. }) => {
                    let _ = state.with_current(|current| {
                        if current.scan_id == scan_id {
                            current.traces.insert(trace.ip, trace);
                        }
                    });
                }
                Some(other) => {
                    flush(&mut pending, &mut progress);
                    let _ = app.emit(EVENT_SCAN, other);
                }
            },
            _ = ticker.tick() => flush(&mut pending, &mut progress),
        }
    }
}
