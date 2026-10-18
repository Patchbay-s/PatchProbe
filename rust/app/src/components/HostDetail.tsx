import { useCallback, useEffect, useRef, useState } from "react";
import { api, errorMessage } from "../api";
import type {
  Annotations,
  Host,
  IpAnnotation,
  NameTrace,
  NmapResult,
  Outcome,
  SnmpSystemInfo,
  TracerouteHop,
  UdpPortResult,
} from "../types";
import { DEVICE_ICON, DEVICE_LABEL, STATUS_LABEL, TECHNIQUE_LABEL, formatLatency, schemeForPort } from "../util";

interface Props {
  host: Host;
  annotation: IpAnnotation | null;
  nmapAvailable: boolean;
  nmapHint: string;
  tracerouteAvailable: boolean;
  sandboxed: boolean;
  udpPorts: number[];
  onClose: () => void;
  onAnnotations: (a: Annotations) => void;
  onHostsUpdated: (hosts: Host[]) => void;
  notify: (kind: "error" | "warning" | "info", text: string) => void;
}

type TaskState<T> = { status: "idle" } | { status: "running" } | { status: "done"; data: T } | { status: "error"; message: string };

/// Exécute une commande longue (nmap, traceroute…) avec annulation et état d'affichage.
function useTask<T>(run: () => Promise<T>, cancelKey?: string) {
  const [state, setState] = useState<TaskState<T>>({ status: "idle" });
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
      // Fermeture du panneau : le processus ou les sockets en cours sont arrêtés.
      if (cancelKey) api.cancelTool(cancelKey).catch(() => undefined);
    };
  }, [cancelKey]);
  const start = useCallback(() => {
    setState({ status: "running" });
    run()
      .then((data) => alive.current && setState({ status: "done", data }))
      .catch((e) => alive.current && setState({ status: "error", message: errorMessage(e) }));
  }, [run]);
  const cancel = useCallback(() => {
    if (cancelKey) api.cancelTool(cancelKey).catch(() => undefined);
  }, [cancelKey]);
  return { state, start, cancel };
}

function OutcomeBadge({ outcome }: { outcome: Outcome }) {
  const map: Record<Outcome["kind"], [string, string]> = {
    found: ["Trouvé", "ok"],
    notFound: ["Pas de nom", "neutral"],
    timeout: ["Délai dépassé", "warn"],
    error: ["Erreur", "bad"],
    skipped: ["Non tenté", "muted"],
  };
  const [label, tone] = map[outcome.kind];
  return <span className={`badge ${tone}`}>{label}</span>;
}

function outcomeDetail(outcome: Outcome): string {
  return "detail" in outcome ? outcome.detail : "aucune réponse avant le délai";
}

function TraceTable({ trace }: { trace: NameTrace }) {
  return (
    <>
      <p className="hint">
        {trace.chosen ? (
          <>
            Nom retenu : <strong>{trace.chosen.name}</strong> (via {TECHNIQUE_LABEL[trace.chosen.technique]})
          </>
        ) : (
          "Aucune technique n'a trouvé de nom."
        )}
      </p>
      <table className="mini">
        <thead>
          <tr>
            <th>Technique</th>
            <th>Résultat</th>
            <th>Détail</th>
            <th>Durée</th>
          </tr>
        </thead>
        <tbody>
          {trace.results.map((r, i) => (
            <tr key={`${r.technique}-${i}`}>
              <td>{TECHNIQUE_LABEL[r.technique]}</td>
              <td>
                <OutcomeBadge outcome={r.outcome} />
              </td>
              <td className="wrap">{outcomeDetail(r.outcome)}</td>
              <td className="num">{r.outcome.kind === "skipped" ? "—" : `${r.durationMs} ms`}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}

function Section({ title, children, actions }: { title: string; children: React.ReactNode; actions?: React.ReactNode }) {
  return (
    <section className="detail-section">
      <header>
        <h3>{title}</h3>
        <div className="section-actions">{actions}</div>
      </header>
      {children}
    </section>
  );
}

function RunButtons<T>({ task, label }: { task: ReturnType<typeof useTask<T>>; label: string }) {
  return task.state.status === "running" ? (
    <>
      <span className="spinner" aria-hidden />
      <button onClick={task.cancel}>Annuler</button>
    </>
  ) : (
    <button onClick={task.start}>{task.state.status === "idle" ? label : "Relancer"}</button>
  );
}

export function HostDetail({ host, annotation, nmapAvailable, nmapHint, tracerouteAvailable, sandboxed, udpPorts, onClose, onAnnotations, onHostsUpdated, notify }: Props) {
  const ip = host.ip;
  const [note, setNote] = useState(annotation?.note ?? "");
  const [vendorInput, setVendorInput] = useState(host.vendorOverridden ? host.vendor ?? "" : "");
  const [sshUser, setSshUser] = useState("");
  const [scanTrace, setScanTrace] = useState<NameTrace | null>(null);
  const noteTimer = useRef<number | undefined>(undefined);

  useEffect(() => {
    api.getNameTrace(ip).then(setScanTrace).catch(() => setScanTrace(null));
  }, [ip, host.hostname]);

  // Note : enregistrée 400 ms après la dernière frappe (et le store débounce l'écriture disque).
  const onNoteChange = (value: string) => {
    setNote(value);
    window.clearTimeout(noteTimer.current);
    noteTimer.current = window.setTimeout(() => {
      api.setNote(ip, value).catch((e) => notify("error", errorMessage(e)));
    }, 400);
  };
  useEffect(() => () => window.clearTimeout(noteTimer.current), []);

  const diagnostic = useTask(useCallback(() => api.diagnoseName(ip), [ip]));
  const snmp = useTask(useCallback(() => api.snmpWalk(ip), [ip]), `snmp:${ip}`);
  const udp = useTask(useCallback(() => api.udpScan(ip), [ip]), `udp:${ip}`);
  const trace = useTask(useCallback(() => api.traceroute(ip), [ip]), `traceroute:${ip}`);
  const nmap = useTask(useCallback(() => api.runNmap(ip), [ip]), `nmap:${ip}`);

  const toggleFavorite = () =>
    api
      .setFavorite(ip, !(annotation?.favorite ?? false))
      .then(onAnnotations)
      .catch((e) => notify("error", errorMessage(e)));

  const saveVendor = () => {
    if (!host.mac) return;
    api
      .setVendorOverride(host.mac, vendorInput)
      .then(onHostsUpdated)
      .catch((e) => notify("error", errorMessage(e)));
  };

  const wake = () => {
    if (!host.mac) return;
    api
      .wakeOnLan(host.mac)
      .then(() => notify("info", `Paquet magique envoyé à ${host.mac}.`))
      .catch((e) => notify("error", errorMessage(e)));
  };

  const open = (port?: number, scheme?: "http" | "https") => api.openHost(ip, port, scheme).catch((e) => notify("error", errorMessage(e)));
  const openSsh = () => api.openSsh(ip, sshUser).catch((e) => notify("error", errorMessage(e)));
  const openFtp = () => api.openFtp(ip).catch((e) => notify("error", errorMessage(e)));

  return (
    <aside className="detail" aria-label={`Détail de ${ip}`}>
      <header className="detail-header">
        <span className="detail-icon">{DEVICE_ICON[host.deviceType]}</span>
        <div>
          <h2>{host.hostname ?? ip}</h2>
          <div className="muted">
            {DEVICE_LABEL[host.deviceType]} · {STATUS_LABEL[host.status]}
          </div>
        </div>
        <button className="icon-button close" onClick={onClose} aria-label="Fermer">
          ✕
        </button>
      </header>

      <div className="detail-body">
        <dl className="info-grid">
          <dt>IP</dt>
          <dd className="mono">{ip}</dd>
          <dt>Hostname</dt>
          <dd>
            {host.hostname ?? "—"}
            {host.hostnameSource && <span className="muted"> ({TECHNIQUE_LABEL[host.hostnameSource as keyof typeof TECHNIQUE_LABEL] ?? host.hostnameSource})</span>}
          </dd>
          <dt>Latence</dt>
          <dd>{formatLatency(host.latencyMs)}</dd>
          <dt>OS probable</dt>
          <dd>
            {host.probableOs ?? "—"}
            {host.ttl !== null && <span className="muted"> (TTL {host.ttl})</span>}
          </dd>
          <dt>MAC</dt>
          <dd className="mono">{host.mac ??
              (host.isLikelyRouted
                ? "Non disponible — hôte routé (pas un voisin Ethernet direct)"
                : sandboxed
                  ? "Non disponible dans la version App Store"
                  : "—")}</dd>
          <dt>Fabricant</dt>
          <dd>
            {host.vendor ?? "—"} {host.vendorOverridden && <span className="badge">modifié</span>}
          </dd>
          <dt>Ports ouverts</dt>
          <dd className="mono">{host.openPorts.length ? host.openPorts.join(", ") : "—"}</dd>
        </dl>

        <div className="button-row">
          <span className="muted">Ouvrir :</span>
          <button onClick={() => open(undefined, "http")}>http://</button>
          <button onClick={() => open(undefined, "https")}>https://</button>
          {host.openPorts.map((port) => (
            <button key={port} onClick={() => open(port)} title={`${schemeForPort(port)}://${ip}:${port}`}>
              {port}
            </button>
          ))}
        </div>

        <Section title="Connexion SSH et FTP">
          <div className="inline-form">
            <input
              value={sshUser}
              onChange={(e) => setSshUser(e.target.value)}
              placeholder="Utilisateur SSH (optionnel)"
              aria-label="Utilisateur SSH"
              autoCapitalize="off"
              spellCheck={false}
            />
            <button onClick={openSsh} title={`Ouvre un terminal : ssh ${sshUser.trim() ? `${sshUser.trim()}@` : ""}${ip}`}>
              SSH{host.openPorts.includes(22) ? "" : " (port 22 non détecté)"}
            </button>
            <button onClick={openFtp} title={`Ouvre ftp://${ip}`}>
              FTP{host.openPorts.includes(21) ? "" : " (port 21 non détecté)"}
            </button>
          </div>
          <p className="hint">Le mot de passe est demandé par le terminal ou le client FTP du système, jamais enregistré par PatchProbe.</p>
        </Section>

        <Section title="Favori et note">
          <label className="checkbox">
            <input type="checkbox" checked={annotation?.favorite ?? false} onChange={toggleFavorite} /> Favori
          </label>
          <textarea value={note} onChange={(e) => onNoteChange(e.target.value)} placeholder="Note libre sur cet appareil…" rows={3} />
        </Section>

        {host.mac && (
          <Section title="Fabricant et réveil">
            <div className="inline-form">
              <input value={vendorInput} onChange={(e) => setVendorInput(e.target.value)} placeholder="Correction du fabricant (vide = OUI)" />
              <button onClick={saveVendor}>Enregistrer</button>
              <button onClick={wake} title="Wake-on-LAN (paquet magique)">
                Réveiller (WoL)
              </button>
            </div>
          </Section>
        )}

        <Section title="Diagnostic du nom" actions={<RunButtons task={diagnostic} label="Relancer chaque technique" />}>
          {diagnostic.state.status === "done" ? (
            <TraceTable trace={diagnostic.state.data} />
          ) : diagnostic.state.status === "error" ? (
            <p className="error-text">{diagnostic.state.message}</p>
          ) : scanTrace ? (
            <>
              <p className="hint">Résultat de chaque technique pendant le scan :</p>
              <TraceTable trace={scanTrace} />
            </>
          ) : (
            <p className="hint">
              Interroge PTR, DNS du routeur, mDNS, NBNS, SMB, LLMNR, SNMP et le titre web individuellement, avec le résultat exact
              et la durée de chaque étape.
            </p>
          )}
        </Section>

        <Section title="SNMP" actions={<RunButtons task={snmp} label="Interroger (walk système)" />}>
          {snmp.state.status === "done" ? (
            snmp.state.data ? (
              <SnmpView info={snmp.state.data} />
            ) : (
              <p className="hint">Aucune réponse SNMP (probablement désactivé ou filtré sur cet hôte).</p>
            )
          ) : snmp.state.status === "error" ? (
            <p className="error-text">{snmp.state.message}</p>
          ) : (
            <p className="hint">sysDescr, sysUpTime, sysContact, sysName, sysLocation, ifNumber (community « public »).</p>
          )}
        </Section>

        <Section title="Ports UDP" actions={<RunButtons task={udp} label="Scanner (DNS, NTP, SNMP, SSDP…)" />}>
          {udp.state.status === "done" ? (
            <UdpView results={udp.state.data} />
          ) : udp.state.status === "error" ? (
            <p className="error-text">{udp.state.message}</p>
          ) : (
            <p className="hint">Sonde {udpPorts.length} ports UDP courants ({udpPorts.join(", ")}).</p>
          )}
        </Section>

        <Section title="Traceroute" actions={tracerouteAvailable ? <RunButtons task={trace} label="Tracer la route" /> : undefined}>
          {!tracerouteAvailable ? (
            <p className="hint">Traceroute n'est pas disponible dans la version App Store.</p>
          ) : trace.state.status === "done" ? (
            <HopsView hops={trace.state.data} />
          ) : trace.state.status === "error" ? (
            <p className="error-text">{trace.state.message}</p>
          ) : trace.state.status === "running" ? (
            <p className="hint">Sonde chaque saut jusqu'à 30 (jusqu'à ~30 s)…</p>
          ) : null}
        </Section>

        <Section title="Nmap" actions={nmapAvailable ? <RunButtons task={nmap} label="Scan approfondi (-sV)" /> : undefined}>
          {!nmapAvailable ? (
            <p className="hint">{nmapHint}</p>
          ) : nmap.state.status === "done" ? (
            <NmapView result={nmap.state.data} />
          ) : nmap.state.status === "error" ? (
            <p className="error-text">{nmap.state.message}</p>
          ) : nmap.state.status === "running" ? (
            <p className="hint">Détection de version en cours — de quelques secondes à ~45 s selon les ports.</p>
          ) : null}
        </Section>
      </div>
    </aside>
  );
}

function SnmpView({ info }: { info: SnmpSystemInfo }) {
  const rows: [string, string | number | null][] = [
    ["Description", info.sysDescr],
    ["Nom système", info.sysName],
    ["Emplacement", info.sysLocation],
    ["Contact", info.sysContact],
    ["Uptime", info.sysUpTime],
    ["Interfaces", info.ifNumber],
  ];
  return (
    <dl className="info-grid">
      {rows
        .filter(([, value]) => value !== null && value !== "")
        .map(([label, value]) => (
          <div key={label} className="contents">
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
    </dl>
  );
}

const UDP_LABEL = { open: "ouvert", closed: "fermé", openOrFiltered: "ouvert|filtré" } as const;

function UdpView({ results }: { results: UdpPortResult[] }) {
  return (
    <table className="mini">
      <thead>
        <tr>
          <th>Port</th>
          <th>Service</th>
          <th>État</th>
        </tr>
      </thead>
      <tbody>
        {results.map((r) => (
          <tr key={r.port}>
            <td className="mono">{r.port}/udp</td>
            <td>{r.service ?? "—"}</td>
            <td>
              <span className={`badge ${r.status === "open" ? "ok" : r.status === "closed" ? "muted" : "warn"}`}>{UDP_LABEL[r.status]}</span>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HopsView({ hops }: { hops: TracerouteHop[] }) {
  return (
    <table className="mini">
      <thead>
        <tr>
          <th>Saut</th>
          <th>Adresse</th>
          <th>RTT</th>
        </tr>
      </thead>
      <tbody>
        {hops.map((hop) => (
          <tr key={hop.hop}>
            <td className="num">{hop.hop}</td>
            <td className="mono">{hop.address ?? "*"}</td>
            <td className="num">{hop.rttMs !== null ? `${hop.rttMs.toFixed(1)} ms` : "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function NmapView({ result }: { result: NmapResult }) {
  const ports = result.report.ports;
  return (
    <>
      <p className="hint mono">{result.commandLine}</p>
      {ports.length ? (
        <table className="mini">
          <thead>
            <tr>
              <th>Port</th>
              <th>État</th>
              <th>Service</th>
              <th>Détails</th>
            </tr>
          </thead>
          <tbody>
            {ports.map((p) => (
              <tr key={`${p.protocol}/${p.port}`}>
                <td className="mono">
                  {p.port}/{p.protocol}
                </td>
                <td>{p.state}</td>
                <td>{p.service ?? "—"}</td>
                <td className="wrap">{[p.product, p.version].filter(Boolean).join(" ") || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="hint">Aucun port dans le rapport XML — sortie brute :</p>
      )}
      <details>
        <summary>Sortie brute</summary>
        <pre className="raw">{result.rawOutput}</pre>
      </details>
    </>
  );
}
