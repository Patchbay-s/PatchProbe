import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, errorMessage, onHosts, onScanCompleted, onScanEvent } from "./api";
import type { Annotations, AppSettings, Bootstrap, ExportFormat, Host, PortPresetKind, ScanPhase, TimingPreset } from "./types";
import { Toolbar } from "./components/Toolbar";
import { ResultsTable } from "./components/ResultsTable";
import { HostDetail } from "./components/HostDetail";
import { HistoryPanel } from "./components/HistoryPanel";
import { SiteProfilesPanel } from "./components/SiteProfilesPanel";
import { SettingsPanel } from "./components/SettingsPanel";
import { compareHosts, groupHosts, matchesSearch, type SortState } from "./util";

export interface ScanProgress {
  running: boolean;
  scanId: number;
  scanned: number;
  total: number;
  up: number;
  portCount: number;
  phase: ScanPhase | null;
}

type Panel = "history" | "profiles" | "settings" | null;

const IDLE: ScanProgress = { running: false, scanId: 0, scanned: 0, total: 0, up: 0, portCount: 0, phase: null };

const PHASE_LABEL: Record<ScanPhase, string> = {
  hosts: "Sondes des hôtes",
  arpSweep: "Balayage ARP",
  discovery: "Découverte Bonjour/SSDP",
};

export default function App() {
  const [boot, setBoot] = useState<Bootstrap | null>(null);
  const [settings, setSettings] = useState<AppSettings | null>(null);
  const [range, setRange] = useState("");
  const [ports, setPorts] = useState("");
  const [hosts, setHosts] = useState<Map<string, Host>>(new Map());
  const [progress, setProgress] = useState<ScanProgress>(IDLE);
  const [annotations, setAnnotations] = useState<Annotations>({});
  const [messages, setMessages] = useState<{ id: number; kind: "error" | "warning" | "info"; text: string }[]>([]);
  const [selectedIp, setSelectedIp] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [sort, setSort] = useState<SortState>({ key: "ip", ascending: true });
  const [panel, setPanel] = useState<Panel>(null);
  const scanIdRef = useRef(0);
  const messageId = useRef(0);

  const notify = useCallback((kind: "error" | "warning" | "info", text: string) => {
    messageId.current += 1;
    const id = messageId.current;
    setMessages((list) => [...list.filter((m) => m.text !== text), { id, kind, text }]);
    if (kind === "info") setTimeout(() => setMessages((list) => list.filter((m) => m.id !== id)), 5000);
  }, []);

  const mergeHosts = useCallback((incoming: Host[]) => {
    setHosts((previous) => {
      const next = new Map(previous);
      for (const host of incoming) next.set(host.ip, host);
      return next;
    });
  }, []);

  // Démarrage : réglages, réseau détecté, résultats déjà présents.
  useEffect(() => {
    api
      .bootstrap()
      .then((b) => {
        setBoot(b);
        setSettings(b.settings);
        setAnnotations(b.annotations);
        setRange(b.rangeInput || b.settings.recentRanges[0] || b.defaultRange || "");
        setPorts(b.settings.portsInput);
        setHosts(new Map(b.hosts.map((h) => [h.ip, h])));
        b.warnings.forEach((w) => notify("warning", w));
      })
      .catch((e) => notify("error", errorMessage(e)));
  }, [notify]);

  // Événements du scan (filtrés sur le scan courant).
  useEffect(() => {
    const unlisten = [
      onHosts((batch) => {
        if (batch.scanId === scanIdRef.current) mergeHosts(batch.hosts);
      }),
      onScanEvent((event) => {
        if (event.scanId !== scanIdRef.current) return;
        switch (event.type) {
          case "progress":
            setProgress((p) => ({ ...p, scanned: event.scanned, total: event.total, up: event.up }));
            break;
          case "phase":
            setProgress((p) => ({ ...p, phase: event.phase }));
            break;
          case "warning":
            notify("warning", event.message);
            break;
          case "finished":
            setProgress((p) => ({ ...p, up: event.up }));
            break;
          case "started":
            break;
        }
      }),
      onScanCompleted((done) => {
        if (done.scanId !== scanIdRef.current) return;
        setProgress((p) => ({ ...p, running: false, phase: null, up: done.up }));
        if (done.error) notify("error", done.error);
        else if (done.cancelled) notify("info", "Scan interrompu.");
      }),
    ];
    return () => unlisten.forEach((p) => p.then((fn) => fn()));
  }, [mergeHosts, notify]);

  const startScan = useCallback(
    async (rangeOverride?: string) => {
      const target = (rangeOverride ?? range).trim();
      try {
        const started = await api.startScan(target, ports);
        scanIdRef.current = started.scanId;
        setHosts(new Map());
        setProgress({ running: true, scanId: started.scanId, scanned: 0, total: started.total, up: 0, portCount: started.portCount, phase: "hosts" });
        setMessages((list) => list.filter((m) => m.kind === "info"));
        setSettings((s) => (s ? { ...s, portsInput: ports, recentRanges: [target, ...s.recentRanges.filter((r) => r !== target)].slice(0, 5) } : s));
      } catch (e) {
        notify("error", errorMessage(e));
      }
    },
    [range, ports, notify],
  );

  const stopScan = useCallback(() => {
    api.cancelScan().catch((e) => notify("error", errorMessage(e)));
  }, [notify]);

  const scanCurrentNetwork = useCallback(async () => {
    try {
      const info = await api.detectNetwork();
      if (info.range) {
        setRange(info.range);
        await startScan(info.range);
      }
    } catch (e) {
      notify("error", errorMessage(e));
    }
  }, [startScan, notify]);

  const applyPortPreset = useCallback(
    async (kind: PortPresetKind) => {
      const updated = await api.applyPortPreset(kind);
      setSettings(updated);
      setPorts(updated.portsInput);
    },
    [],
  );

  const applyTimingPreset = useCallback(async (preset: TimingPreset) => {
    setSettings(await api.applyTimingPreset(preset));
  }, []);

  const saveSettings = useCallback(async (next: AppSettings) => {
    setSettings(await api.saveSettings(next));
  }, []);

  const exportResults = useCallback(
    async (format: ExportFormat) => {
      try {
        const defaultPath = await api.exportFileName(format);
        const path = await save({ defaultPath, filters: [{ name: format.toUpperCase(), extensions: [format] }] });
        if (!path) return;
        await api.exportScan(format, path, settings?.hideDownHosts ?? true);
        notify("info", `Exporté vers ${path}`);
      } catch (e) {
        notify("error", errorMessage(e));
      }
    },
    [settings, notify],
  );

  const loadedFromHistory = useCallback((scanId: number, rangeInput: string, loaded: Host[]) => {
    scanIdRef.current = scanId;
    setProgress({ ...IDLE, scanId, scanned: loaded.length, total: loaded.length, up: loaded.length });
    setRange(rangeInput);
    setHosts(new Map(loaded.map((h) => [h.ip, h])));
    setPanel(null);
  }, []);

  const hideDown = settings?.hideDownHosts ?? true;
  const grouping = settings?.grouping ?? "none";

  const visibleHosts = useMemo(() => {
    const list = [...hosts.values()].filter((h) => (!hideDown || h.status === "up") && matchesSearch(h, search));
    list.sort((a, b) => compareHosts(a, b, sort));
    return list;
  }, [hosts, hideDown, search, sort]);

  const groups = useMemo(() => groupHosts(visibleHosts, grouping), [visibleHosts, grouping]);
  const selectedHost = selectedIp ? hosts.get(selectedIp) ?? null : null;
  const percent = progress.total > 0 ? Math.min(100, (progress.scanned / progress.total) * 100) : 0;

  return (
    <div className="app">
      <Toolbar
        range={range}
        ports={ports}
        onRange={setRange}
        onPorts={setPorts}
        running={progress.running}
        onScan={() => startScan()}
        onStop={stopScan}
        onScanCurrentNetwork={scanCurrentNetwork}
        recentRanges={settings?.recentRanges ?? []}
        portPresets={boot?.portPresets ?? []}
        lastPortPreset={settings?.lastPortPreset ?? null}
        onPortPreset={applyPortPreset}
        settings={settings}
        onTimingPreset={applyTimingPreset}
        onExport={exportResults}
        onOpenPanel={setPanel}
        hasResults={hosts.size > 0}
      />

      <div className="statusbar">
        <div className={`progress ${progress.running ? "active" : ""}`} aria-label="Progression du scan">
          <div className="progress-fill" style={{ width: `${progress.running || progress.total ? percent : 0}%` }} />
        </div>
        <span className="status-text">
          {progress.total > 0
            ? `${progress.scanned}/${progress.total} hôtes scannés · ${progress.up} actif(s)`
            : boot?.interface
              ? `Interface ${boot.interface.name} — ${boot.interface.ip}/${boot.interface.prefixLen}${boot.gateway ? ` — passerelle ${boot.gateway}` : ""}`
              : "Prêt"}
          {progress.running && progress.phase ? ` · ${PHASE_LABEL[progress.phase]}…` : ""}
        </span>
        <div className="table-controls">
          <input
            className="search"
            type="search"
            placeholder="Rechercher (IP, nom, fabricant, MAC, OS, port)…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          <label>
            Grouper par{" "}
            <select
              value={grouping}
              onChange={(e) => settings && saveSettings({ ...settings, grouping: e.target.value as AppSettings["grouping"] })}
            >
              <option value="none">Aucun</option>
              <option value="subnet">Sous-réseau</option>
              <option value="vendor">Fabricant</option>
              <option value="status">Statut</option>
            </select>
          </label>
          <label className="checkbox">
            <input
              type="checkbox"
              checked={hideDown}
              onChange={(e) => settings && saveSettings({ ...settings, hideDownHosts: e.target.checked })}
            />
            Masquer les injoignables
          </label>
        </div>
      </div>

      {messages.length > 0 && (
        <div className="messages">
          {messages.map((m) => (
            <div key={m.id} className={`message ${m.kind}`}>
              <span>{m.text}</span>
              <button className="link" onClick={() => setMessages((list) => list.filter((x) => x.id !== m.id))} aria-label="Fermer">
                ✕
              </button>
            </div>
          ))}
        </div>
      )}

      <main className="content">
        <ResultsTable
          groups={groups}
          grouped={grouping !== "none"}
          sort={sort}
          onSort={setSort}
          annotations={annotations}
          selectedIp={selectedIp}
          onSelect={setSelectedIp}
          onPing={(ip) => api.pingHost(ip).then((h) => mergeHosts([h])).catch((e) => notify("error", errorMessage(e)))}
          onOpen={(ip) => api.openHost(ip).catch((e) => notify("error", errorMessage(e)))}
          showMac={!(boot?.sandboxed ?? false)}
          emptyText={
            hosts.size === 0
              ? progress.running
                ? "Scan en cours…"
                : "Saisissez une plage puis cliquez sur Scanner."
              : search
                ? `Aucun résultat pour « ${search} »`
                : "Aucun hôte actif (décochez « Masquer les injoignables » pour tout voir)."
          }
        />
        {selectedHost && boot && (
          <HostDetail
            key={selectedHost.ip}
            host={selectedHost}
            annotation={annotations[selectedHost.ip] ?? null}
            nmapAvailable={boot.nmapAvailable}
            nmapHint={boot.nmapHint}
            tracerouteAvailable={boot.tracerouteAvailable}
            sandboxed={boot.sandboxed}
            udpPorts={boot.udpPorts}
            onClose={() => setSelectedIp(null)}
            onAnnotations={setAnnotations}
            onHostsUpdated={mergeHosts}
            notify={notify}
          />
        )}
      </main>

      {panel === "history" && <HistoryPanel onClose={() => setPanel(null)} onLoaded={loadedFromHistory} notify={notify} />}
      {panel === "profiles" && <SiteProfilesPanel onClose={() => setPanel(null)} notify={notify} hasResults={hosts.size > 0} />}
      {panel === "settings" && settings && boot && (
        <SettingsPanel
          settings={settings}
          portPresets={boot.portPresets}
          dataDir={boot.dataDir}
          os={boot.os}
          onSave={saveSettings}
          onTimingPreset={applyTimingPreset}
          onPortPreset={applyPortPreset}
          onClearCache={() => api.clearResolutionCache().then(() => notify("info", "Cache de résolution vidé."))}
          onClose={() => setPanel(null)}
        />
      )}
    </div>
  );
}
