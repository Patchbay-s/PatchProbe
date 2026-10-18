//! Commandes Tauri appelées par l'interface. Toutes renvoient `Result<_, String>` avec un
//! message en français prêt à afficher.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

use patchprobe_core::app_settings::AppSettings;
use patchprobe_core::diff::{ScanDiff, SiteProfileDiff};
use patchprobe_core::engine::SystemProbe;
use patchprobe_core::model::{Annotations, Host, HostStatus, SiteProfile};
use patchprobe_core::net::udp_scan::{self, UdpPortResult, DEFAULT_UDP_PORTS};
use patchprobe_core::net::{snmp_walk, wol};
use patchprobe_core::parsers::traceroute::TracerouteHop;
use patchprobe_core::proto::snmp::SnmpSystemInfo;
use patchprobe_core::range::InterfaceInfo;
use patchprobe_core::resolve::{NameResolution, NameTrace, ResolveMode, Resolver, ResolverConfig};
use patchprobe_core::store::HistoryEntry;
use patchprobe_core::{export, PortPresetKind, TimingPreset, DEFAULT_TCP_PORTS};
use patchprobe_platform::tools::{self, NmapResult};
use patchprobe_platform::Platform;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use uuid::Uuid;

use crate::scan::{self, emit_hosts, ScanStarted};
use crate::state::{AppState, CurrentScan};

type CmdResult<T> = Result<T, String>;

fn parse_ip(ip: &str) -> CmdResult<Ipv4Addr> {
    ip.trim().parse().map_err(|_| format!("Adresse IPv4 invalide : « {ip} »."))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortPresetInfo {
    kind: PortPresetKind,
    label: &'static str,
    ports: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bootstrap {
    settings: AppSettings,
    interface: Option<InterfaceInfo>,
    default_range: Option<String>,
    gateway: Option<Ipv4Addr>,
    os: &'static str,
    warnings: Vec<String>,
    port_presets: Vec<PortPresetInfo>,
    default_ports: String,
    udp_ports: Vec<u16>,
    nmap_available: bool,
    nmap_hint: &'static str,
    traceroute_available: bool,
    /// Édition App Store (bac à sable) : pas de MAC ni de fabricant.
    sandboxed: bool,
    annotations: Annotations,
    data_dir: String,
    range_input: String,
    hosts: Vec<Host>,
}

#[tauri::command]
pub async fn bootstrap(state: State<'_, AppState>) -> CmdResult<Bootstrap> {
    let interface = state.platform.active_interface().await;
    let gateway = state.platform.default_gateway(interface.as_ref()).await;
    let (range_input, hosts) = state.with_current(|c| (c.range_input.clone(), c.hosts_vec()))?;
    Ok(Bootstrap {
        settings: state.settings.get(),
        default_range: interface.as_ref().map(InterfaceInfo::scan_range_text),
        interface,
        gateway,
        os: state.platform.os_name(),
        warnings: state.load_warnings.clone(),
        port_presets: PortPresetKind::ALL
            .into_iter()
            .map(|kind| PortPresetInfo { kind, label: kind.label(), ports: kind.ports_string() })
            .collect(),
        default_ports: DEFAULT_TCP_PORTS.iter().map(u16::to_string).collect::<Vec<_>>().join(","),
        udp_ports: DEFAULT_UDP_PORTS.to_vec(),
        nmap_available: tools::find_nmap().is_some(),
        nmap_hint: tools::nmap_install_hint(),
        traceroute_available: tools::traceroute_available(),
        sandboxed: patchprobe_platform::is_sandboxed(),
        annotations: state.annotations.get(),
        data_dir: state.paths.base().display().to_string(),
        range_input,
        hosts,
    })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInfo {
    interface: Option<InterfaceInfo>,
    range: Option<String>,
}

/// Plage du réseau actuel, détectée à nouveau (changement de Wi-Fi depuis le lancement).
#[tauri::command]
pub async fn detect_network(state: State<'_, AppState>) -> CmdResult<NetworkInfo> {
    let interface = state.platform.active_interface().await;
    let range = interface.as_ref().map(InterfaceInfo::scan_range_text);
    if interface.is_none() {
        return Err("Aucune interface réseau active détectée.".into());
    }
    Ok(NetworkInfo { interface, range })
}

#[tauri::command]
pub fn start_scan(app: AppHandle, state: State<'_, AppState>, range: String, ports: String) -> CmdResult<ScanStarted> {
    scan::start(&app, &state, &range, &ports)
}

#[tauri::command]
pub fn cancel_scan(state: State<'_, AppState>) {
    if let Ok(mut slot) = state.scan_cancel.lock() {
        if let Some(token) = slot.take() {
            token.cancel();
        }
    }
}

/// Re-ping d'une ligne : met à jour statut, latence et TTL.
#[tauri::command]
pub async fn ping_host(app: AppHandle, state: State<'_, AppState>, ip: String) -> CmdResult<Host> {
    let ip = parse_ip(&ip)?;
    let timeout = Duration::from_millis(state.settings.get().scan.ping_timeout_ms);
    let reply = state.platform.ping(ip, timeout).await;
    let (scan_id, host) = state.with_current(|current| {
        let host = current.hosts.entry(ip).or_insert_with(|| Host::new(ip));
        host.status = if reply.alive || !host.open_ports.is_empty() { HostStatus::Up } else { HostStatus::Down };
        host.latency_ms = reply.latency_ms;
        if reply.alive {
            host.apply_ttl(reply.ttl);
        }
        host.refresh_derived();
        (current.scan_id, host.clone())
    })?;
    emit_hosts(&app, scan_id, vec![host.clone()]);
    Ok(host)
}

#[tauri::command]
pub fn open_url(state: State<'_, AppState>, url: String) -> CmdResult<()> {
    state.platform.open_url(&url).map_err(|e| e.to_string())
}

/// Ouvre un hôte dans le navigateur : port précis, schéma forcé, ou meilleure supposition
/// (https si 443, http si 80, sinon premier port ouvert).
#[tauri::command]
pub fn open_host(
    state: State<'_, AppState>,
    ip: String,
    port: Option<u16>,
    scheme: Option<String>,
) -> CmdResult<String> {
    let ip = parse_ip(&ip)?;
    let url = match (port, scheme.as_deref()) {
        (Some(port), _) => patchprobe_core::model::url_for(ip, port),
        (None, Some("https")) => format!("https://{ip}"),
        (None, Some("http")) => format!("http://{ip}"),
        _ => state.with_current(|c| c.hosts.get(&ip).map(Host::browser_url))?.unwrap_or_else(|| format!("http://{ip}")),
    };
    state.platform.open_url(&url).map_err(|e| e.to_string())?;
    Ok(url)
}

#[tauri::command]
pub fn open_ssh(state: State<'_, AppState>, ip: String, user: Option<String>, port: Option<u16>) -> CmdResult<()> {
    let ip = parse_ip(&ip)?;
    let terminal = state.settings.get().ssh_terminal;
    state.platform.open_ssh(ip, user.as_deref(), port.unwrap_or(22), &terminal).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn open_ftp(state: State<'_, AppState>, ip: String, port: Option<u16>) -> CmdResult<()> {
    let ip = parse_ip(&ip)?;
    state.platform.open_ftp(ip, port.unwrap_or(21)).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn get_name_trace(state: State<'_, AppState>, ip: String) -> CmdResult<Option<NameTrace>> {
    let ip = parse_ip(&ip)?;
    state.with_current(|c| c.traces.get(&ip).cloned())
}

/// Relance chaque technique de résolution individuellement (cache ignoré).
#[tauri::command]
pub async fn diagnose_name(state: State<'_, AppState>, ip: String) -> CmdResult<NameTrace> {
    let ip = parse_ip(&ip)?;
    let settings = state.settings.get().scan;
    let interface = state.platform.active_interface().await;
    let gateway = state.platform.default_gateway(interface.as_ref()).await;
    let ports = state.with_current(|c| c.hosts.get(&ip).map(|h| h.open_ports.clone()).unwrap_or_default())?;
    let resolver = Resolver::new(ResolverConfig::from_settings(&settings, gateway), state.resolution_cache.shared());
    let trace = resolver.resolve(ip, &ports, ResolveMode::Diagnostic).await;
    state.resolution_cache.touch();
    Ok(trace)
}

#[tauri::command]
pub async fn run_nmap(state: State<'_, AppState>, ip: String) -> CmdResult<NmapResult> {
    let ip = parse_ip(&ip)?;
    let key = format!("nmap:{ip}");
    let (id, token) = state.start_tool(&key);
    let result = tools::run_nmap(ip, &token).await;
    state.finish_tool(&key, id);
    result.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn cancel_tool(state: State<'_, AppState>, key: String) {
    state.cancel_tool(&key);
}

#[tauri::command]
pub async fn udp_scan(state: State<'_, AppState>, ip: String) -> CmdResult<Vec<UdpPortResult>> {
    let ip = parse_ip(&ip)?;
    let key = format!("udp:{ip}");
    let (id, token) = state.start_tool(&key);
    let result =
        token.run_until_cancelled(udp_scan::scan_ports(ip, &DEFAULT_UDP_PORTS, Duration::from_millis(800), 8)).await;
    state.finish_tool(&key, id);
    result.ok_or_else(|| "Scan UDP annulé.".to_owned())
}

#[tauri::command]
pub async fn snmp_walk(state: State<'_, AppState>, ip: String) -> CmdResult<Option<SnmpSystemInfo>> {
    let ip = parse_ip(&ip)?;
    let key = format!("snmp:{ip}");
    let (id, token) = state.start_tool(&key);
    let target = SocketAddrV4::new(ip, 161);
    let result = token.run_until_cancelled(snmp_walk::system_info(target, "public", Duration::from_millis(800))).await;
    state.finish_tool(&key, id);
    result.ok_or_else(|| "Interrogation SNMP annulée.".to_owned())
}

#[tauri::command]
pub async fn traceroute(state: State<'_, AppState>, ip: String) -> CmdResult<Vec<TracerouteHop>> {
    let ip = parse_ip(&ip)?;
    let key = format!("traceroute:{ip}");
    let (id, token) = state.start_tool(&key);
    let result = tools::run_traceroute(ip, &token).await;
    state.finish_tool(&key, id);
    result.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn wake_on_lan(mac: String) -> CmdResult<()> {
    wol::send(&mac, None).await.map_err(|e| e.to_string())
}

#[tauri::command]
pub fn set_favorite(state: State<'_, AppState>, ip: String, favorite: bool) -> CmdResult<Annotations> {
    let ip = parse_ip(&ip)?;
    state.annotations.update(|a| a.set_favorite(ip, favorite, chrono::Utc::now()));
    Ok(state.annotations.get())
}

/// Appelée pendant la frappe (côté interface, avec un léger délai) ; l'écriture disque est
/// elle-même débouncée par le store.
#[tauri::command]
pub fn set_note(state: State<'_, AppState>, ip: String, note: String) -> CmdResult<()> {
    let ip = parse_ip(&ip)?;
    state.annotations.update(|a| a.set_note(ip, &note, chrono::Utc::now()));
    match state.annotations.last_error() {
        Some(e) => Err(format!("Échec de l'enregistrement — vérifiez l'espace disque disponible ({e}).")),
        None => Ok(()),
    }
}

/// Correction manuelle du fabricant (vide = suppression) ; renvoie les hôtes mis à jour.
#[tauri::command]
pub fn set_vendor_override(
    app: AppHandle,
    state: State<'_, AppState>,
    mac: String,
    vendor: String,
) -> CmdResult<Vec<Host>> {
    state.vendor_overrides.update(|o| o.set(&mac, &vendor));
    let overrides = state.vendor_overrides.get();
    let target = patchprobe_core::oui::normalize_mac(&mac);
    let (scan_id, updated) = state.with_current(|current| {
        let mut updated = Vec::new();
        for host in current.hosts.values_mut() {
            let same = host.mac.as_deref().and_then(patchprobe_core::oui::normalize_mac) == target;
            if !same {
                continue;
            }
            let mut fresh = host.clone();
            fresh.vendor = host.mac.as_deref().and_then(patchprobe_core::oui::vendor).map(str::to_owned);
            fresh.vendor_overridden = false;
            fresh = overrides.apply(&fresh);
            fresh.refresh_derived();
            *host = fresh.clone();
            updated.push(fresh);
        }
        (current.scan_id, updated)
    })?;
    emit_hosts(&app, scan_id, updated.clone());
    Ok(updated)
}

#[tauri::command]
pub fn save_settings(state: State<'_, AppState>, settings: AppSettings) -> AppSettings {
    let settings = settings.sanitized();
    state.settings.update(|s| *s = settings.clone());
    settings
}

#[tauri::command]
pub fn apply_timing_preset(state: State<'_, AppState>, preset: TimingPreset) -> AppSettings {
    state.settings.update(|s| s.scan.apply_preset(preset));
    state.settings.get()
}

#[tauri::command]
pub fn apply_port_preset(state: State<'_, AppState>, kind: PortPresetKind) -> AppSettings {
    state.settings.update(|s| s.apply_port_preset(kind));
    state.settings.get()
}

#[tauri::command]
pub fn clear_resolution_cache(state: State<'_, AppState>) {
    state.resolution_cache.update(|c| c.clear());
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryList {
    entries: Vec<HistoryEntry>,
    warnings: Vec<String>,
}

#[tauri::command]
pub async fn list_history(state: State<'_, AppState>) -> CmdResult<HistoryList> {
    let history = state.history.clone();
    let (entries, warnings) =
        tauri::async_runtime::spawn_blocking(move || history.list()).await.map_err(|e| e.to_string())?;
    Ok(HistoryList { entries, warnings })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadedScan {
    scan_id: u64,
    range_input: String,
    hosts: Vec<Host>,
}

/// Recharge un scan passé dans la table sans toucher au réseau.
#[tauri::command]
pub fn load_history(state: State<'_, AppState>, id: Uuid) -> CmdResult<LoadedScan> {
    let snapshot = state.history.load(id).ok_or("Scan introuvable ou illisible dans l'historique.")?;
    state.cancel_all();
    let overrides = state.vendor_overrides.get();
    let hosts: Vec<Host> = snapshot.to_hosts().iter().map(|h| overrides.apply(h)).collect();
    let scan_id = state.scan_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    state.with_current(|current| {
        *current = CurrentScan {
            scan_id,
            range_input: snapshot.range_input.clone(),
            hosts: hosts.iter().map(|h| (h.ip, h.clone())).collect(),
            traces: Default::default(),
        };
    })?;
    Ok(LoadedScan { scan_id, range_input: snapshot.range_input, hosts })
}

#[tauri::command]
pub fn delete_history(state: State<'_, AppState>, id: Uuid) -> bool {
    state.history.delete(id)
}

#[tauri::command]
pub fn diff_history(state: State<'_, AppState>, a: Uuid, b: Uuid) -> CmdResult<ScanDiff> {
    let first = state.history.load(a).ok_or("Premier scan introuvable.")?;
    let second = state.history.load(b).ok_or("Second scan introuvable.")?;
    Ok(ScanDiff::compute(&first, &second))
}

#[tauri::command]
pub fn list_site_profiles(state: State<'_, AppState>) -> Vec<SiteProfile> {
    state.site_profiles.get()
}

/// Ajoute ou remplace (même identifiant) un profil.
#[tauri::command]
pub fn save_site_profile(state: State<'_, AppState>, profile: SiteProfile) -> Vec<SiteProfile> {
    state.site_profiles.update(|profiles| match profiles.iter_mut().find(|p| p.id == profile.id) {
        Some(existing) => *existing = profile,
        None => profiles.push(profile),
    });
    state.site_profiles.get()
}

#[tauri::command]
pub fn delete_site_profile(state: State<'_, AppState>, id: Uuid) -> Vec<SiteProfile> {
    state.site_profiles.update(|profiles| profiles.retain(|p| p.id != id));
    state.site_profiles.get()
}

#[tauri::command]
pub fn create_site_profile_from_scan(state: State<'_, AppState>, name: String) -> CmdResult<SiteProfile> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Donnez un nom au profil.".into());
    }
    let hosts = state.with_current(|c| c.live_hosts())?;
    if hosts.is_empty() {
        return Err("Aucun hôte actif dans les résultats : lancez d'abord un scan.".into());
    }
    let profile = SiteProfile::from_hosts(name, &hosts);
    state.site_profiles.update(|p| p.push(profile.clone()));
    Ok(profile)
}

#[tauri::command]
pub fn compare_site_profile(state: State<'_, AppState>, id: Uuid) -> CmdResult<SiteProfileDiff> {
    let profile = state.site_profiles.get().into_iter().find(|p| p.id == id).ok_or("Profil introuvable.")?;
    let hosts = state.with_current(|c| c.live_hosts())?;
    Ok(SiteProfileDiff::compute(&profile, &hosts))
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Csv,
    Json,
    Html,
}

/// Écrit l'export dans `path` (choisi par l'utilisateur via la boîte de dialogue).
#[tauri::command]
pub async fn export_scan(
    state: State<'_, AppState>,
    format: ExportFormat,
    path: String,
    only_up: bool,
) -> CmdResult<String> {
    let (range_input, mut hosts) = state.with_current(|c| (c.range_input.clone(), c.hosts_vec()))?;
    if only_up {
        hosts.retain(|h| h.status == HostStatus::Up);
    }
    let content = match format {
        ExportFormat::Csv => export::csv(&hosts),
        ExportFormat::Json => export::json(&hosts),
        ExportFormat::Html => {
            export::html(&hosts, &range_input, &chrono::Local::now().format("%d/%m/%Y %H:%M").to_string())
        }
    };
    let target = std::path::PathBuf::from(&path);
    // Écriture directe, pas `write_atomic` : dans le bac à sable de l'App Store, seul le fichier
    // choisi dans le panneau d'enregistrement est accessible, pas un fichier temporaire voisin.
    tauri::async_runtime::spawn_blocking(move || std::fs::write(&target, content.as_bytes()))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| format!("Impossible d'écrire {path} : {e}"))?;
    Ok(path)
}

/// Suffixe horodaté proposé pour le nom du fichier exporté.
#[tauri::command]
pub fn export_file_name(format: ExportFormat) -> String {
    let ext = match format {
        ExportFormat::Csv => "csv",
        ExportFormat::Json => "json",
        ExportFormat::Html => "html",
    };
    format!("patchprobe-export-{}.{ext}", export::timestamp_suffix(chrono::Local::now()))
}

/// Pour l'affichage de l'état des outils dans le panneau de détail.
#[tauri::command]
pub fn nmap_status() -> (bool, &'static str) {
    (tools::find_nmap().is_some(), tools::nmap_install_hint())
}
