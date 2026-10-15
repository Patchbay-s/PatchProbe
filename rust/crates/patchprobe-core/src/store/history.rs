//! Historique des scans : un fichier JSON par scan — port de `ScanHistoryService.swift`.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use super::file::{self, LoadStatus, StoreError};
use crate::model::snapshot::ScanSnapshot;

/// Nombre maximal de scans conservés (les plus anciens sont supprimés).
pub const MAX_SNAPSHOTS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HistoryEntry {
    pub id: Uuid,
    pub date: DateTime<Utc>,
    pub range_input: String,
    pub host_count: usize,
}

#[derive(Debug, Clone)]
pub struct HistoryStore {
    dir: PathBuf,
}

impl HistoryStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path_for(&self, id: Uuid) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    pub fn save(&self, snapshot: &ScanSnapshot) -> Result<(), StoreError> {
        file::save(&self.path_for(snapshot.id), snapshot)?;
        self.prune();
        Ok(())
    }

    fn read_all(&self) -> (Vec<ScanSnapshot>, Vec<String>) {
        let mut snapshots = Vec::new();
        let mut warnings = Vec::new();
        let Ok(entries) = fs::read_dir(&self.dir) else { return (snapshots, warnings) };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            // Seuls les fichiers `<uuid>.json` sont des scans (ni temporaires ni mis de côté).
            let is_snapshot = name.strip_suffix(".json").is_some_and(|stem| Uuid::parse_str(stem).is_ok());
            if !is_snapshot {
                continue;
            }
            match file::load::<Option<ScanSnapshot>>(&path) {
                (Some(snapshot), _) => snapshots.push(snapshot),
                (None, status) => {
                    if let Some(warning) = status.warning("Historique") {
                        warnings.push(warning);
                    }
                }
            }
        }
        snapshots.sort_by_key(|s| std::cmp::Reverse(s.date));
        (snapshots, warnings)
    }

    /// Scans du plus récent au plus ancien, et avertissements pour les fichiers mis de côté.
    pub fn list(&self) -> (Vec<HistoryEntry>, Vec<String>) {
        let (snapshots, warnings) = self.read_all();
        let entries = snapshots
            .into_iter()
            .map(|s| HistoryEntry { id: s.id, date: s.date, range_input: s.range_input, host_count: s.hosts.len() })
            .collect();
        (entries, warnings)
    }

    pub fn load(&self, id: Uuid) -> Option<ScanSnapshot> {
        match file::load::<Option<ScanSnapshot>>(&self.path_for(id)) {
            (Some(snapshot), LoadStatus::Loaded) => Some(snapshot),
            _ => None,
        }
    }

    pub fn delete(&self, id: Uuid) -> bool {
        fs::remove_file(self.path_for(id)).is_ok()
    }

    fn prune(&self) {
        let (snapshots, _) = self.read_all();
        for old in snapshots.iter().skip(MAX_SNAPSHOTS) {
            let _ = fs::remove_file(self.path_for(old.id));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, HostStatus};
    use chrono::TimeZone;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("patchprobe-history-{}-{:x}", std::process::id(), rand::random::<u32>()))
    }

    fn snapshot(secs: i64, ip: &str) -> ScanSnapshot {
        let mut host = Host::new(ip.parse().unwrap());
        host.status = HostStatus::Up;
        ScanSnapshot::from_scan("198.51.100.0/24", &[host], Utc.timestamp_opt(secs, 0).unwrap()).unwrap()
    }

    #[test]
    fn save_list_load_delete() {
        let store = HistoryStore::new(temp_dir());
        let older = snapshot(100, "198.51.100.1");
        let newer = snapshot(200, "198.51.100.2");
        store.save(&older).unwrap();
        store.save(&newer).unwrap();
        fs::write(store.dir().join(format!("{}.json", Uuid::new_v4())), b"garbage").unwrap();
        let (entries, warnings) = store.list();
        assert_eq!(entries.iter().map(|e| e.id).collect::<Vec<_>>(), [newer.id, older.id]);
        assert_eq!(entries[0].host_count, 1);
        assert_eq!(warnings.len(), 1, "le fichier corrompu est signalé et mis de côté");
        assert_eq!(store.load(older.id), Some(older.clone()));
        assert!(store.delete(older.id));
        assert!(store.load(older.id).is_none());
        assert_eq!(store.list().0.len(), 1);
        fs::remove_dir_all(store.dir()).unwrap();
    }
}
