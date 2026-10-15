import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import type { HistoryEntry, Host, HostChangeKind, ScanDiff } from "../types";
import { formatDate } from "../util";
import { Modal } from "./Modal";

interface Props {
  onClose: () => void;
  onLoaded: (scanId: number, rangeInput: string, hosts: Host[]) => void;
  notify: (kind: "error" | "warning" | "info", text: string) => void;
}

const KIND_TITLE: Record<HostChangeKind, string> = {
  new: "Apparus",
  gone: "Disparus",
  changed: "Modifiés",
  unchanged: "Inchangés",
};

export function HistoryPanel({ onClose, onLoaded, notify }: Props) {
  const [entries, setEntries] = useState<HistoryEntry[] | null>(null);
  const [selected, setSelected] = useState<string[]>([]);
  const [diff, setDiff] = useState<ScanDiff | null>(null);

  const refresh = () =>
    api
      .listHistory()
      .then((list) => {
        setEntries(list.entries);
        list.warnings.forEach((w) => notify("warning", w));
      })
      .catch((e) => notify("error", errorMessage(e)));

  useEffect(() => {
    refresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggle = (id: string) =>
    setSelected((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s.slice(-1), id]));

  const load = (id: string) =>
    api
      .loadHistory(id)
      .then((loaded) => onLoaded(loaded.scanId, loaded.rangeInput, loaded.hosts))
      .catch((e) => notify("error", errorMessage(e)));

  const remove = (id: string) =>
    api
      .deleteHistory(id)
      .then(() => {
        setSelected((s) => s.filter((x) => x !== id));
        refresh();
      })
      .catch((e) => notify("error", errorMessage(e)));

  const compare = () => {
    if (selected.length !== 2) return;
    api
      .diffHistory(selected[0], selected[1])
      .then(setDiff)
      .catch((e) => notify("error", errorMessage(e)));
  };

  if (diff) {
    return (
      <Modal title="Comparaison de deux scans" onClose={onClose} wide>
        <p className="hint">
          Du {formatDate(diff.older.date)} ({diff.older.rangeInput}) au {formatDate(diff.newer.date)} ({diff.newer.rangeInput})
        </p>
        {(["new", "gone", "changed"] as HostChangeKind[]).map((kind) => {
          const list = diff.entries.filter((e) => e.kind === kind);
          return (
            <section key={kind} className="diff-section">
              <h3>
                {KIND_TITLE[kind]} ({list.length})
              </h3>
              {list.length === 0 ? (
                <p className="muted">Aucun.</p>
              ) : (
                <ul className="diff-list">
                  {list.map((e) => (
                    <li key={e.ip}>
                      <span className="mono">{e.ip}</span> {(e.after ?? e.before)?.hostname ?? ""}
                      {e.changes.map((c) => (
                        <div key={c} className="change">
                          {c}
                        </div>
                      ))}
                    </li>
                  ))}
                </ul>
              )}
            </section>
          );
        })}
        <p className="muted">Inchangés : {diff.entries.filter((e) => e.kind === "unchanged").length}</p>
        <button onClick={() => setDiff(null)}>← Retour à l'historique</button>
      </Modal>
    );
  }

  return (
    <Modal title="Historique des scans" onClose={onClose} wide>
      {entries === null ? (
        <p className="hint">Chargement…</p>
      ) : entries.length === 0 ? (
        <p className="hint">Aucun scan enregistré. Chaque scan terminé avec au moins un hôte actif est sauvegardé automatiquement.</p>
      ) : (
        <>
          <p className="hint">Cochez deux scans pour les comparer.</p>
          <table className="mini full">
            <thead>
              <tr>
                <th />
                <th>Date</th>
                <th>Plage</th>
                <th>Hôtes actifs</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {entries.map((entry) => (
                <tr key={entry.id}>
                  <td>
                    <input type="checkbox" checked={selected.includes(entry.id)} onChange={() => toggle(entry.id)} />
                  </td>
                  <td>{formatDate(entry.date)}</td>
                  <td className="mono">{entry.rangeInput}</td>
                  <td className="num">{entry.hostCount}</td>
                  <td className="row-actions">
                    <button onClick={() => load(entry.id)}>Charger</button>
                    <button onClick={() => remove(entry.id)}>Supprimer</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <button className="primary" disabled={selected.length !== 2} onClick={compare}>
            Comparer les deux scans cochés
          </button>
        </>
      )}
    </Modal>
  );
}
