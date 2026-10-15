import { useState } from "react";
import type { AppSettings, ExportFormat, PortPresetInfo, PortPresetKind, TimingPreset } from "../types";

interface Props {
  range: string;
  ports: string;
  onRange: (value: string) => void;
  onPorts: (value: string) => void;
  running: boolean;
  onScan: () => void;
  onStop: () => void;
  onScanCurrentNetwork: () => void;
  recentRanges: string[];
  portPresets: PortPresetInfo[];
  lastPortPreset: PortPresetKind | null;
  onPortPreset: (kind: PortPresetKind) => void;
  settings: AppSettings | null;
  onTimingPreset: (preset: TimingPreset) => void;
  onExport: (format: ExportFormat) => void;
  onOpenPanel: (panel: "history" | "profiles" | "settings") => void;
  hasResults: boolean;
}

function timingPresetOf(settings: AppSettings | null): TimingPreset | "custom" {
  if (!settings) return "approfondi";
  const s = settings.scan;
  if (s.portTimeoutMs === 250 && s.nameTimeoutMs === 500 && s.webTitleTimeoutMs === 800) return "rapide";
  if (s.portTimeoutMs === 400 && s.nameTimeoutMs === 1000 && s.webTitleTimeoutMs === 1200) return "approfondi";
  return "custom";
}

/// Barre d'outils : le bouton Scanner suit immédiatement le champ Ports et n'est jamais replié
/// dans un menu (la barre passe à la ligne si la fenêtre est étroite).
export function Toolbar(props: Props) {
  const [exportOpen, setExportOpen] = useState(false);
  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    if (props.running) props.onStop();
    else props.onScan();
  };
  const timing = timingPresetOf(props.settings);

  return (
    <form className="toolbar" onSubmit={submit}>
      <label className="field range-field">
        <span>Plage</span>
        <input
          list="recent-ranges"
          value={props.range}
          onChange={(e) => props.onRange(e.target.value)}
          placeholder="192.0.2.0/24, 192.0.2.1-254 ou une IP"
          spellCheck={false}
        />
        <datalist id="recent-ranges">
          {props.recentRanges.map((r) => (
            <option key={r} value={r} />
          ))}
        </datalist>
      </label>
      <label className="field ports-field">
        <span>Ports</span>
        <input
          value={props.ports}
          onChange={(e) => props.onPorts(e.target.value)}
          placeholder="par défaut (homelab)"
          spellCheck={false}
          title="Port seul (8080), plage (1-1024) ou liste (22,80,443,8000-8010)"
        />
      </label>
      <button type="submit" className={`primary scan-button ${props.running ? "stop" : ""}`}>
        {props.running ? "Arrêter" : "Scanner"}
      </button>

      <label className="field compact">
        <span>Preset ports</span>
        <select
          value={props.lastPortPreset ?? ""}
          onChange={(e) => e.target.value && props.onPortPreset(e.target.value as PortPresetKind)}
        >
          <option value="">—</option>
          {props.portPresets.map((p) => (
            <option key={p.kind} value={p.kind}>
              {p.label}
            </option>
          ))}
        </select>
      </label>
      <label className="field compact">
        <span>Timing</span>
        <select value={timing} onChange={(e) => e.target.value !== "custom" && props.onTimingPreset(e.target.value as TimingPreset)}>
          <option value="rapide">{timing === "rapide" ? "✓ " : ""}Rapide</option>
          <option value="approfondi">{timing === "approfondi" ? "✓ " : ""}Approfondi</option>
          {timing === "custom" && <option value="custom">Personnalisé</option>}
        </select>
      </label>
      <button type="button" onClick={props.onScanCurrentNetwork} disabled={props.running} title="Re-détecte le réseau actuel et le scanne">
        Ce réseau
      </button>

      <div className="spacer" />

      <button type="button" onClick={() => props.onOpenPanel("history")}>
        Historique
      </button>
      <button type="button" onClick={() => props.onOpenPanel("profiles")}>
        Profils de site
      </button>
      <div className="menu">
        <button type="button" onClick={() => setExportOpen((o) => !o)} disabled={!props.hasResults} aria-expanded={exportOpen}>
          Exporter ▾
        </button>
        {exportOpen && (
          <div className="menu-items" onMouseLeave={() => setExportOpen(false)}>
            {(["csv", "json", "html"] as ExportFormat[]).map((format) => (
              <button
                type="button"
                key={format}
                onClick={() => {
                  setExportOpen(false);
                  props.onExport(format);
                }}
              >
                {format.toUpperCase()}
              </button>
            ))}
          </div>
        )}
      </div>
      <button type="button" onClick={() => props.onOpenPanel("settings")} title="Réglages">
        Réglages
      </button>
    </form>
  );
}
