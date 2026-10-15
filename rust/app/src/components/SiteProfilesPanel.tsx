import { useEffect, useState } from "react";
import { api, errorMessage } from "../api";
import type { SiteProfile, SiteProfileDiff, SiteProfileMatchKind } from "../types";
import { Modal } from "./Modal";

interface Props {
  onClose: () => void;
  notify: (kind: "error" | "warning" | "info", text: string) => void;
  hasResults: boolean;
}

const KIND_ORDER: SiteProfileMatchKind[] = ["missing", "unexpected", "mismatch", "matched"];
const KIND_TITLE: Record<SiteProfileMatchKind, string> = {
  missing: "Manquants",
  unexpected: "Inattendus",
  mismatch: "Écarts",
  matched: "Conformes",
};

function newId(): string {
  return crypto.randomUUID();
}

export function SiteProfilesPanel({ onClose, notify, hasResults }: Props) {
  const [profiles, setProfiles] = useState<SiteProfile[]>([]);
  const [editing, setEditing] = useState<SiteProfile | null>(null);
  const [diff, setDiff] = useState<SiteProfileDiff | null>(null);
  const [newName, setNewName] = useState("");

  useEffect(() => {
    api.listSiteProfiles().then(setProfiles).catch((e) => notify("error", errorMessage(e)));
  }, [notify]);

  const createFromScan = () =>
    api
      .createSiteProfileFromScan(newName)
      .then((profile) => {
        setProfiles((list) => [...list, profile]);
        setNewName("");
        setEditing(profile);
      })
      .catch((e) => notify("error", errorMessage(e)));

  const createEmpty = () => {
    const name = newName.trim() || "Nouveau site";
    setEditing({ id: newId(), name, entries: [] });
    setNewName("");
  };

  const saveEditing = () => {
    if (!editing) return;
    const cleaned: SiteProfile = {
      ...editing,
      entries: editing.entries.map((e) => ({ ...e, ip: e.ip?.trim() || null, mac: e.mac?.trim() || null })),
    };
    api
      .saveSiteProfile(cleaned)
      .then((list) => {
        setProfiles(list);
        setEditing(null);
        notify("info", `Profil « ${cleaned.name} » enregistré.`);
      })
      .catch((e) => notify("error", errorMessage(e)));
  };

  const remove = (id: string) =>
    api
      .deleteSiteProfile(id)
      .then(setProfiles)
      .catch((e) => notify("error", errorMessage(e)));

  const compare = (id: string) =>
    api
      .compareSiteProfile(id)
      .then(setDiff)
      .catch((e) => notify("error", errorMessage(e)));

  if (diff) {
    return (
      <Modal title={`Comparaison au profil « ${diff.profile.name} »`} onClose={onClose} wide>
        {KIND_ORDER.map((kind) => {
          const list = diff.entries.filter((e) => e.kind === kind);
          return (
            <section key={kind} className={`diff-section kind-${kind}`}>
              <h3>
                {KIND_TITLE[kind]} ({list.length})
              </h3>
              {list.length === 0 ? (
                <p className="muted">Aucun.</p>
              ) : (
                <ul className="diff-list">
                  {list.map((e) => (
                    <li key={e.id}>
                      <strong>{e.entry?.label ?? e.host?.hostname ?? e.host?.ip}</strong>{" "}
                      <span className="mono muted">
                        {[e.entry?.ip ?? e.host?.ip, e.entry?.mac ?? e.host?.mac].filter(Boolean).join(" · ")}
                      </span>
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
        <button onClick={() => setDiff(null)}>← Retour aux profils</button>
      </Modal>
    );
  }

  if (editing) {
    const update = (index: number, field: "label" | "ip" | "mac", value: string) =>
      setEditing({ ...editing, entries: editing.entries.map((e, i) => (i === index ? { ...e, [field]: value } : e)) });
    return (
      <Modal title="Édition du profil de site" onClose={onClose} wide>
        <label className="field">
          <span>Nom</span>
          <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
        </label>
        <table className="mini full">
          <thead>
            <tr>
              <th>Libellé</th>
              <th>IP</th>
              <th>MAC (prioritaire)</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {editing.entries.map((entry, index) => (
              <tr key={entry.id}>
                <td>
                  <input value={entry.label} onChange={(e) => update(index, "label", e.target.value)} />
                </td>
                <td>
                  <input className="mono" value={entry.ip ?? ""} onChange={(e) => update(index, "ip", e.target.value)} />
                </td>
                <td>
                  <input className="mono" value={entry.mac ?? ""} onChange={(e) => update(index, "mac", e.target.value)} />
                </td>
                <td>
                  <button onClick={() => setEditing({ ...editing, entries: editing.entries.filter((_, i) => i !== index) })}>Supprimer</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="button-row">
          <button onClick={() => setEditing({ ...editing, entries: [...editing.entries, { id: newId(), label: "", ip: null, mac: null }] })}>
            + Ajouter une entrée
          </button>
          <div className="spacer" />
          <button onClick={() => setEditing(null)}>Annuler</button>
          <button className="primary" onClick={saveEditing} disabled={!editing.name.trim()}>
            Enregistrer
          </button>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Profils de site" onClose={onClose} wide>
      <p className="hint">
        Inventaire attendu d'un site (libellé + IP et/ou MAC). « Comparer » confronte le profil aux hôtes actifs du scan actuel, la
        MAC primant sur l'IP (le DHCP change les IP, pas les MAC).
      </p>
      <div className="inline-form">
        <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Nom du nouveau profil" />
        <button className="primary" onClick={createFromScan} disabled={!hasResults || !newName.trim()}>
          Créer depuis le scan actuel
        </button>
        <button onClick={createEmpty}>Créer vide</button>
      </div>
      {profiles.length === 0 ? (
        <p className="hint">Aucun profil.</p>
      ) : (
        <table className="mini full">
          <thead>
            <tr>
              <th>Nom</th>
              <th>Entrées</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {profiles.map((p) => (
              <tr key={p.id}>
                <td>{p.name}</td>
                <td className="num">{p.entries.length}</td>
                <td className="row-actions">
                  <button className="primary" onClick={() => compare(p.id)} disabled={!hasResults}>
                    Comparer au profil
                  </button>
                  <button onClick={() => setEditing(p)}>Modifier</button>
                  <button onClick={() => remove(p.id)}>Supprimer</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Modal>
  );
}
