// Accès typé aux commandes et événements Tauri.

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AppSettings,
  Annotations,
  Bootstrap,
  ExportFormat,
  Host,
  HistoryEntry,
  HostsBatch,
  InterfaceInfo,
  NameTrace,
  NmapResult,
  PortPresetKind,
  ScanCompleted,
  ScanDiff,
  ScanEvent,
  ScanStarted,
  SiteProfile,
  SiteProfileDiff,
  SnmpSystemInfo,
  TimingPreset,
  TracerouteHop,
  UdpPortResult,
} from "./types";

export const api = {
  bootstrap: () => invoke<Bootstrap>("bootstrap"),
  detectNetwork: () => invoke<{ interface: InterfaceInfo | null; range: string | null }>("detect_network"),
  startScan: (range: string, ports: string) => invoke<ScanStarted>("start_scan", { range, ports }),
  cancelScan: () => invoke<void>("cancel_scan"),
  pingHost: (ip: string) => invoke<Host>("ping_host", { ip }),
  openUrl: (url: string) => invoke<void>("open_url", { url }),
  openHost: (ip: string, port?: number, scheme?: "http" | "https") =>
    invoke<string>("open_host", { ip, port: port ?? null, scheme: scheme ?? null }),
  getNameTrace: (ip: string) => invoke<NameTrace | null>("get_name_trace", { ip }),
  diagnoseName: (ip: string) => invoke<NameTrace>("diagnose_name", { ip }),
  runNmap: (ip: string) => invoke<NmapResult>("run_nmap", { ip }),
  cancelTool: (key: string) => invoke<void>("cancel_tool", { key }),
  udpScan: (ip: string) => invoke<UdpPortResult[]>("udp_scan", { ip }),
  snmpWalk: (ip: string) => invoke<SnmpSystemInfo | null>("snmp_walk", { ip }),
  traceroute: (ip: string) => invoke<TracerouteHop[]>("traceroute", { ip }),
  wakeOnLan: (mac: string) => invoke<void>("wake_on_lan", { mac }),
  setFavorite: (ip: string, favorite: boolean) => invoke<Annotations>("set_favorite", { ip, favorite }),
  setNote: (ip: string, note: string) => invoke<void>("set_note", { ip, note }),
  setVendorOverride: (mac: string, vendor: string) => invoke<Host[]>("set_vendor_override", { mac, vendor }),
  saveSettings: (settings: AppSettings) => invoke<AppSettings>("save_settings", { settings }),
  applyTimingPreset: (preset: TimingPreset) => invoke<AppSettings>("apply_timing_preset", { preset }),
  applyPortPreset: (kind: PortPresetKind) => invoke<AppSettings>("apply_port_preset", { kind }),
  clearResolutionCache: () => invoke<void>("clear_resolution_cache"),
  listHistory: () => invoke<{ entries: HistoryEntry[]; warnings: string[] }>("list_history"),
  loadHistory: (id: string) => invoke<{ scanId: number; rangeInput: string; hosts: Host[] }>("load_history", { id }),
  deleteHistory: (id: string) => invoke<boolean>("delete_history", { id }),
  diffHistory: (a: string, b: string) => invoke<ScanDiff>("diff_history", { a, b }),
  listSiteProfiles: () => invoke<SiteProfile[]>("list_site_profiles"),
  saveSiteProfile: (profile: SiteProfile) => invoke<SiteProfile[]>("save_site_profile", { profile }),
  deleteSiteProfile: (id: string) => invoke<SiteProfile[]>("delete_site_profile", { id }),
  createSiteProfileFromScan: (name: string) => invoke<SiteProfile>("create_site_profile_from_scan", { name }),
  compareSiteProfile: (id: string) => invoke<SiteProfileDiff>("compare_site_profile", { id }),
  exportScan: (format: ExportFormat, path: string, onlyUp: boolean) =>
    invoke<string>("export_scan", { format, path, onlyUp }),
  exportFileName: (format: ExportFormat) => invoke<string>("export_file_name", { format }),
};

export function onHosts(handler: (batch: HostsBatch) => void): Promise<UnlistenFn> {
  return listen<HostsBatch>("scan://hosts", (e) => handler(e.payload));
}

export function onScanEvent(handler: (event: ScanEvent) => void): Promise<UnlistenFn> {
  return listen<ScanEvent>("scan://event", (e) => handler(e.payload));
}

export function onScanCompleted(handler: (event: ScanCompleted) => void): Promise<UnlistenFn> {
  return listen<ScanCompleted>("scan://completed", (e) => handler(e.payload));
}

/// Message lisible d'une erreur de commande (les commandes rejettent avec une chaîne).
export function errorMessage(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}
