//! Fichier JSON versionné : écriture atomique (temporaire + rename), enveloppe avec version de
//! schéma, fichier illisible mis de côté au lieu d'être écrasé — port de `PersistedJSONFile`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Version courante du schéma des fichiers.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StoreError {
    #[error("écriture de {path} impossible : {message}")]
    Write { path: String, message: String },
    #[error("sérialisation impossible : {0}")]
    Serialize(String),
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeOut<'a, T> {
    schema_version: u32,
    data: &'a T,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvelopeIn {
    schema_version: u32,
    data: serde_json::Value,
}

/// Ce qui s'est passé au chargement (remonté à l'interface).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadStatus {
    /// Pas de fichier : valeur par défaut.
    Missing,
    Loaded,
    /// Fichier illisible, déplacé vers `backup` ; valeur par défaut utilisée.
    Quarantined {
        backup: PathBuf,
    },
    /// Fichier d'une version plus récente de l'app : copié vers `backup`, valeur par défaut.
    NewerSchema {
        version: u32,
        backup: PathBuf,
    },
}

impl LoadStatus {
    /// Message d'avertissement pour l'utilisateur, le cas échéant.
    pub fn warning(&self, label: &str) -> Option<String> {
        match self {
            Self::Missing | Self::Loaded => None,
            Self::Quarantined { backup } => Some(format!(
                "{label} : fichier illisible, mis de côté dans « {} » (valeurs par défaut utilisées).",
                backup.display()
            )),
            Self::NewerSchema { version, backup } => Some(format!(
                "{label} : fichier créé par une version plus récente (schéma {version}), sauvegardé dans « {} ».",
                backup.display()
            )),
        }
    }
}

fn timestamp() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S%.3fZ").to_string()
}

/// `dossier/nom.<étiquette>-<horodatage>.json`.
fn sibling(path: &Path, tag: &str) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "store".into());
    let ext = path.extension().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "json".into());
    path.with_file_name(format!("{stem}.{tag}-{}.{ext}", timestamp()))
}

/// Écrit `bytes` de façon atomique : fichier temporaire dans le même dossier, `fsync`, puis
/// `rename` par-dessus la cible. Un lecteur voit l'ancien ou le nouveau contenu, jamais un
/// fichier à moitié écrit, même en cas de disque plein ou de coupure.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let err = |e: std::io::Error| StoreError::Write { path: path.display().to_string(), message: e.to_string() };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(err)?;
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = dir.join(format!(".{name}.tmp-{}-{:08x}", std::process::id(), rand::random::<u32>()));
    let result = (|| {
        let mut file = fs::File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&temp);
        return Err(err(e));
    }
    #[cfg(unix)]
    if let Ok(dir_handle) = fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(())
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec_pretty(&EnvelopeOut { schema_version: SCHEMA_VERSION, data: value })
        .map_err(|e| StoreError::Serialize(e.to_string()))
}

pub fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    write_atomic(path, &encode(value)?)
}

/// Décode un contenu : enveloppe versionnée, ou ancien format sans enveloppe (schéma 0).
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Option<u32>> {
    if let Ok(envelope) = serde_json::from_slice::<EnvelopeIn>(bytes) {
        if envelope.schema_version > SCHEMA_VERSION {
            return Err(Some(envelope.schema_version));
        }
        return serde_json::from_value(envelope.data).map_err(|_| None);
    }
    serde_json::from_slice(bytes).map_err(|_| None)
}

/// Charge `path`. Ne détruit jamais un fichier existant illisible : il est déplacé (corrompu)
/// ou copié (schéma plus récent) à côté, et la valeur par défaut est renvoyée.
pub fn load<T: DeserializeOwned + Default>(path: &Path) -> (T, LoadStatus) {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (T::default(), LoadStatus::Missing),
        Err(_) => {
            let backup = sibling(path, "unreadable");
            let _ = fs::copy(path, &backup);
            return (T::default(), LoadStatus::Quarantined { backup });
        }
    };
    match decode::<T>(&bytes) {
        Ok(value) => (value, LoadStatus::Loaded),
        Err(Some(version)) => {
            let backup = sibling(path, &format!("schema{version}"));
            let _ = fs::copy(path, &backup);
            (T::default(), LoadStatus::NewerSchema { version, backup })
        }
        Err(None) => {
            let backup = sibling(path, "corrupted");
            if fs::rename(path, &backup).is_err() {
                let _ = fs::copy(path, &backup);
            }
            (T::default(), LoadStatus::Quarantined { backup })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "patchprobe-store-{tag}-{}-{:x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn round_trip_with_schema_version() {
        let dir = temp_dir("rt");
        let path = dir.join("favorites.json");
        let value: BTreeMap<String, String> = [("a".into(), "b".into())].into();
        save(&path, &value).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(raw["schemaVersion"], SCHEMA_VERSION);
        let (loaded, status) = load::<BTreeMap<String, String>>(&path);
        assert_eq!((loaded, status), (value, LoadStatus::Loaded));
        assert_eq!(files_in(&dir), ["favorites.json"], "aucun fichier temporaire résiduel");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_file_gives_default() {
        let dir = temp_dir("missing");
        let (value, status) = load::<Vec<u32>>(&dir.join("nope.json"));
        assert!(value.is_empty());
        assert_eq!(status, LoadStatus::Missing);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupted_file_is_moved_aside_not_overwritten() {
        let dir = temp_dir("corrupt");
        let path = dir.join("site-profiles.json");
        fs::write(&path, b"{ this is not json").unwrap();
        let (value, status) = load::<Vec<u32>>(&path);
        assert!(value.is_empty());
        let LoadStatus::Quarantined { backup } = status else { panic!("{status:?}") };
        assert_eq!(fs::read(&backup).unwrap(), b"{ this is not json");
        assert!(!path.exists());
        assert!(backup.file_name().unwrap().to_string_lossy().starts_with("site-profiles.corrupted-"));
        // Une sauvegarde ultérieure ne touche pas la copie mise de côté.
        save(&path, &vec![1u32]).unwrap();
        assert_eq!(fs::read(&backup).unwrap(), b"{ this is not json");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn newer_schema_is_backed_up() {
        let dir = temp_dir("newer");
        let path = dir.join("settings.json");
        fs::write(&path, br#"{"schemaVersion": 99, "data": {"x": 1}}"#).unwrap();
        let (_, status) = load::<BTreeMap<String, u32>>(&path);
        let LoadStatus::NewerSchema { version: 99, backup } = status else { panic!("{status:?}") };
        assert!(backup.exists());
        assert!(status_warning_mentions(&LoadStatus::NewerSchema { version: 99, backup }));
        fs::remove_dir_all(dir).unwrap();
    }

    fn status_warning_mentions(status: &LoadStatus) -> bool {
        status.warning("Réglages").is_some_and(|w| w.contains("Réglages"))
    }

    #[test]
    fn legacy_unwrapped_format_is_accepted() {
        let dir = temp_dir("legacy");
        let path = dir.join("vendor-overrides.json");
        fs::write(&path, br#"{"02:00:00:00:00:01": "Test vendor"}"#).unwrap();
        let (value, status) = load::<BTreeMap<String, String>>(&path);
        assert_eq!(status, LoadStatus::Loaded);
        assert_eq!(value["02:00:00:00:00:01"], "Test vendor");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn write_into_missing_directory_and_failure_reporting() {
        let dir = temp_dir("nested");
        let path = dir.join("a/b/c.json");
        save(&path, &1u8).unwrap();
        assert!(path.exists());
        // Écrire « dans » un fichier : erreur explicite, pas de panic.
        let err = save(&path.join("impossible.json"), &1u8).unwrap_err();
        assert!(matches!(err, StoreError::Write { .. }));
        fs::remove_dir_all(dir).unwrap();
    }
}
