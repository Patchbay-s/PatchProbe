import { useState } from "react";
import type { AppSettings, PortPresetInfo, PortPresetKind, ScanSettings, TechniqueId, TimingPreset } from "../types";
import { TECHNIQUE_LABEL } from "../util";
import { Modal } from "./Modal";

interface Props {
  settings: AppSettings;
  portPresets: PortPresetInfo[];
  dataDir: string;
  os: string;
  onSave: (settings: AppSettings) => Promise<void>;
  onTimingPreset: (preset: TimingPreset) => Promise<void>;
  onPortPreset: (kind: PortPresetKind) => Promise<void>;
  onClearCache: () => void;
  onClose: () => void;
}

/** Sources proposées comme nom par défaut (miroir de `TechniqueId::PREFERABLE`). */
const NAME_SOURCES: TechniqueId[] = ["webTitle", "gatewayDns", "ptr", "mdns", "nbns", "smb", "llmnr", "snmp"];

type NumericKey = {
  [K in keyof ScanSettings]: ScanSettings[K] extends number ? K : never;
}[keyof ScanSettings];

const NUMERIC_FIELDS: { key: NumericKey; label: string; unit: string; min: number; max: number }[] = [
  { key: "pingTimeoutMs", label: "Timeout ping", unit: "ms", min: 200, max: 10000 },
  { key: "portTimeoutMs", label: "Timeout par port TCP", unit: "ms", min: 50, max: 10000 },
  { key: "nameTimeoutMs", label: "Timeout résolution de nom", unit: "ms", min: 100, max: 10000 },
  { key: "webTitleTimeoutMs", label: "Timeout titre web", unit: "ms", min: 100, max: 10000 },
  { key: "maxTcpConnections", label: "Connexions TCP simultanées (global)", unit: "", min: 1, max: 4096 },
  { key: "maxParallelHosts", label: "Hôtes en parallèle", unit: "", min: 1, max: 1024 },
  { key: "maxParallelNameResolutions", label: "Résolutions de nom en parallèle", unit: "", min: 1, max: 512 },
];

const SSH_TERMINALS: Record<string, { id: string; label: string }[]> = {
  macos: [
    { id: "auto", label: "Automatique (application ssh:// par défaut du Mac, Terminal)" },
    { id: "terminal", label: "Terminal" },
    { id: "iterm", label: "iTerm2" },
  ],
  windows: [
    { id: "auto", label: "Automatique (Windows Terminal s'il est installé, sinon invite de commandes)" },
    { id: "wt", label: "Windows Terminal" },
    { id: "powershell", label: "PowerShell" },
    { id: "cmd", label: "Invite de commandes" },
  ],
  linux: [
    { id: "auto", label: "Automatique (premier terminal trouvé)" },
    { id: "gnome-terminal", label: "GNOME Terminal" },
    { id: "konsole", label: "Konsole" },
    { id: "xfce4-terminal", label: "Xfce Terminal" },
    { id: "xterm", label: "xterm" },
  ],
};

export function SettingsPanel({ settings, portPresets, dataDir, os, onSave, onTimingPreset, onPortPreset, onClearCache, onClose }: Props) {
  const [draft, setDraft] = useState<ScanSettings>(settings.scan);
  const terminals = SSH_TERMINALS[os] ?? SSH_TERMINALS.linux;
  const setNumber = (key: NumericKey, value: string) => {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isNaN(parsed)) setDraft({ ...draft, [key]: parsed });
  };

  return (
    <Modal title="Réglages" onClose={onClose}>
      <section className="settings-section">
        <h3>Performance du scan</h3>
        <div className="button-row">
          <button
            onClick={async () => {
              await onTimingPreset("rapide");
              setDraft({ ...draft, pingTimeoutMs: 1000, portTimeoutMs: 250, nameTimeoutMs: 500, webTitleTimeoutMs: 800 });
            }}
          >
            Rapide
          </button>
          <button
            onClick={async () => {
              await onTimingPreset("approfondi");
              setDraft({ ...draft, pingTimeoutMs: 1000, portTimeoutMs: 400, nameTimeoutMs: 1000, webTitleTimeoutMs: 1200 });
            }}
          >
            Approfondi
          </button>
        </div>
        <div className="settings-grid">
          {NUMERIC_FIELDS.map((field) => (
            <label key={field.key}>
              <span>{field.label}</span>
              <input
                type="number"
                min={field.min}
                max={field.max}
                value={draft[field.key]}
                onChange={(e) => setNumber(field.key, e.target.value)}
              />
              <span className="muted">{field.unit}</span>
            </label>
          ))}
        </div>
        <label className="checkbox">
          <input type="checkbox" checked={draft.runsActiveDiscovery} onChange={(e) => setDraft({ ...draft, runsActiveDiscovery: e.target.checked })} />
          Découverte active (Bonjour/SSDP) en fin de scan
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={draft.runsArpSweep} onChange={(e) => setDraft({ ...draft, runsArpSweep: e.target.checked })} />
          Deuxième passage ARP pour les MAC manquantes
        </label>
        <p className="hint">
          « Rapide » réduit les timeouts ; la découverte active et la passe ARP restent actives (coût fixe par scan). Le plafond de
          connexions TCP est partagé par tous les hôtes et tous les ports ; la résolution de nom a son propre budget.
        </p>
        <button className="primary" onClick={() => onSave({ ...settings, scan: draft })}>
          Enregistrer les réglages
        </button>
      </section>

      <section className="settings-section">
        <h3>Nom des appareils</h3>
        <div className="settings-grid">
          <label className="wide">
            <span>Nom par défaut</span>
            <select
              value={draft.preferredNameSource ?? ""}
              onChange={(e) => setDraft({ ...draft, preferredNameSource: (e.target.value || null) as TechniqueId | null })}
            >
              {NAME_SOURCES.map((source) => (
                <option key={source} value={source}>
                  {TECHNIQUE_LABEL[source]}
                </option>
              ))}
              <option value="">Automatique (DNS du routeur d'abord)</option>
            </select>
          </label>
        </div>
        <p className="hint">
          Nom affiché quand cette source en trouve un ; sinon l'ordre automatique s'applique. Pris en compte au prochain scan.
        </p>
        <button className="primary" onClick={() => onSave({ ...settings, scan: draft })}>
          Enregistrer les réglages
        </button>
      </section>

      <section className="settings-section">
        <h3>Terminal SSH</h3>
        <div className="settings-grid">
          <label className="wide">
            <span>Ouvrir SSH avec</span>
            <select
              value={terminals.some((t) => t.id === settings.sshTerminal) ? settings.sshTerminal : "auto"}
              onChange={(e) => onSave({ ...settings, sshTerminal: e.target.value })}
            >
              {terminals.map((terminal) => (
                <option key={terminal.id} value={terminal.id}>
                  {terminal.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="hint">Appliqué immédiatement au prochain clic sur « SSH » dans la fiche d'un hôte.</p>
      </section>

      <section className="settings-section">
        <h3>Ports par type d'appareil</h3>
        <ul className="preset-list">
          {portPresets.map((preset) => (
            <li key={preset.kind}>
              <button onClick={() => onPortPreset(preset.kind)}>
                {settings.lastPortPreset === preset.kind ? "✓ " : ""}
                {preset.label}
              </button>
              <span className="mono muted">{preset.ports.length > 60 ? `${preset.ports.slice(0, 60)}…` : preset.ports}</span>
            </li>
          ))}
        </ul>
        <p className="hint">Remplace le champ « Ports » de la barre d'outils — reste modifiable ensuite.</p>
      </section>

      <section className="settings-section">
        <h3>Cache de résolution</h3>
        <p className="hint">
          Les noms trouvés sont réutilisés 7 jours lors d'un rescan ; les échecs ne sont mémorisés que 5 minutes. Videz-le si des
          appareils ont changé d'IP.
        </p>
        <button onClick={onClearCache}>Vider le cache</button>
      </section>

      <section className="settings-section">
        <h3>Données</h3>
        <p className="hint mono">{dataDir}</p>
      </section>
    </Modal>
  );
}
