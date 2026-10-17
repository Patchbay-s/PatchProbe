import { useEffect, useMemo, useRef, useState } from "react";
import type { Annotations, Host } from "../types";
import { DEVICE_ICON, DEVICE_LABEL, STATUS_LABEL, formatLatency, type HostGroup, type SortKey, type SortState } from "../util";

interface Props {
  groups: HostGroup[];
  grouped: boolean;
  sort: SortState;
  onSort: (sort: SortState) => void;
  annotations: Annotations;
  selectedIp: string | null;
  onSelect: (ip: string) => void;
  onPing: (ip: string) => void;
  onOpen: (ip: string) => void;
  emptyText: string;
  /** Faux dans l'édition App Store : la table ARP y est inaccessible, MAC et fabricant restent vides. */
  showMac: boolean;
}

type Row = { kind: "group"; key: string; count: number } | { kind: "host"; host: Host };

const ROW_HEIGHT = 30;
const OVERSCAN = 12;

const COLUMNS: { key: SortKey | null; label: string }[] = [
  { key: null, label: "" },
  { key: "ip", label: "IP" },
  { key: "status", label: "Statut" },
  { key: "hostname", label: "Hostname" },
  { key: "latency", label: "Latence" },
  { key: "os", label: "OS probable" },
  { key: "mac", label: "MAC" },
  { key: "vendor", label: "Fabricant" },
  { key: "ports", label: "Ports ouverts" },
  { key: null, label: "Actions" },
];

/// Table virtualisée : seules les lignes visibles sont rendues (un /16 peut afficher des
/// dizaines de milliers d'hôtes).
export function ResultsTable(props: Props) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(600);

  const rows: Row[] = useMemo(() => {
    const out: Row[] = [];
    for (const group of props.groups) {
      if (props.grouped) out.push({ kind: "group", key: group.key, count: group.hosts.length });
      for (const host of group.hosts) out.push({ kind: "host", host });
    }
    return out;
  }, [props.groups, props.grouped]);

  useEffect(() => {
    const element = scrollRef.current;
    if (!element) return;
    const observer = new ResizeObserver(() => setViewport(element.clientHeight));
    observer.observe(element);
    setViewport(element.clientHeight);
    return () => observer.disconnect();
  }, []);

  const first = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
  const last = Math.min(rows.length, Math.ceil((scrollTop + viewport) / ROW_HEIGHT) + OVERSCAN);
  const visible = rows.slice(first, last);

  const columns = props.showMac ? COLUMNS : COLUMNS.filter((c) => c.key !== "mac" && c.key !== "vendor");

  const headerClick = (key: SortKey | null) => {
    if (!key) return;
    props.onSort(props.sort.key === key ? { key, ascending: !props.sort.ascending } : { key, ascending: true });
  };

  return (
    <div className={`table ${props.showMac ? "" : "no-mac"}`}>
      <div className="table-row table-header" role="row">
        {columns.map((column, index) => (
          <div
            key={index}
            role="columnheader"
            className={`cell ${column.key ? "sortable" : ""}`}
            onClick={() => headerClick(column.key)}
            aria-sort={props.sort.key === column.key ? (props.sort.ascending ? "ascending" : "descending") : undefined}
          >
            {column.label}
            {props.sort.key === column.key && column.key ? (props.sort.ascending ? " ▲" : " ▼") : ""}
          </div>
        ))}
      </div>
      <div className="table-body" ref={scrollRef} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}>
        {rows.length === 0 ? (
          <div className="empty">{props.emptyText}</div>
        ) : (
          <div style={{ height: rows.length * ROW_HEIGHT, position: "relative" }}>
            {visible.map((row, offset) => {
              const top = (first + offset) * ROW_HEIGHT;
              if (row.kind === "group") {
                return (
                  <div key={`g:${row.key}`} className="group-row" style={{ top, height: ROW_HEIGHT }}>
                    {row.key} ({row.count})
                  </div>
                );
              }
              const host = row.host;
              const favorite = props.annotations[host.ip]?.favorite ?? false;
              return (
                <div
                  key={host.ip}
                  className={`table-row host-row ${props.selectedIp === host.ip ? "selected" : ""} status-${host.status}`}
                  style={{ top, height: ROW_HEIGHT }}
                  onDoubleClick={() => props.onSelect(host.ip)}
                  role="row"
                >
                  <div className="cell icon" title={DEVICE_LABEL[host.deviceType]}>
                    {DEVICE_ICON[host.deviceType]}
                  </div>
                  <div className="cell mono">
                    {favorite ? "★ " : ""}
                    {host.ip}
                  </div>
                  <div className="cell">
                    <span className={`dot ${host.status}`} /> {STATUS_LABEL[host.status]}
                  </div>
                  <div className="cell" title={host.hostname ?? ""}>
                    {host.hostname ?? <span className="muted">—</span>}
                  </div>
                  <div className="cell">{formatLatency(host.latencyMs)}</div>
                  <div className="cell">{host.probableOs ?? <span className="muted">—</span>}</div>
                  {props.showMac && (
                    <>
                      <div className="cell mono">
                        {host.mac ?? <span className="muted">{host.isLikelyRouted ? "routé" : "—"}</span>}
                      </div>
                      <div className="cell" title={host.vendor ?? ""}>
                        {host.vendor ?? <span className="muted">—</span>}
                        {host.vendorOverridden ? <span className="badge">modifié</span> : null}
                      </div>
                    </>
                  )}
                  <div className="cell mono" title={host.openPorts.join(", ")}>
                    {host.openPorts.length ? host.openPorts.join(", ") : <span className="muted">—</span>}
                  </div>
                  <div className="cell actions">
                    <button className="icon-button" title="Re-ping" onClick={() => props.onPing(host.ip)}>
                      ↻
                    </button>
                    <button className="icon-button" title="Ouvrir dans le navigateur (https si 443, http si 80…)" onClick={() => props.onOpen(host.ip)}>
                      🌐
                    </button>
                    <button className="icon-button" title="Détail" onClick={() => props.onSelect(host.ip)}>
                      ⓘ
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
