//! Persistance JSON dans le dossier de données de l'utilisateur (déterminé par l'application,
//! via la crate `directories`).

pub mod debounce;
pub mod file;
pub mod history;

use std::path::{Path, PathBuf};

pub use debounce::{Store, DEFAULT_DEBOUNCE};
pub use file::{load, save, write_atomic, LoadStatus, StoreError, SCHEMA_VERSION};
pub use history::{HistoryEntry, HistoryStore};

/// Emplacements des fichiers dans le dossier de données.
#[derive(Debug, Clone)]
pub struct DataPaths {
    pub base: PathBuf,
}

impl DataPaths {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self { base: base.into() }
    }

    fn file(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    pub fn settings(&self) -> PathBuf {
        self.file("settings.json")
    }

    pub fn annotations(&self) -> PathBuf {
        self.file("favorites.json")
    }

    pub fn site_profiles(&self) -> PathBuf {
        self.file("site-profiles.json")
    }

    pub fn vendor_overrides(&self) -> PathBuf {
        self.file("vendor-overrides.json")
    }

    pub fn resolution_cache(&self) -> PathBuf {
        self.file("resolution-cache.json")
    }

    pub fn history_dir(&self) -> PathBuf {
        self.base.join("history")
    }

    pub fn base(&self) -> &Path {
        &self.base
    }
}
