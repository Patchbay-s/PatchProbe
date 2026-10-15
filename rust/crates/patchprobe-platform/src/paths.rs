//! Dossier de données de l'utilisateur (crate `directories`) :
//! macOS `~/Library/Application Support/com.patchbay.patchprobe`,
//! Linux `~/.local/share/patchprobe`, Windows `%APPDATA%\patchbay\patchprobe\data`.

use std::path::PathBuf;

use patchprobe_core::store::DataPaths;

pub fn data_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from("com", "patchbay", "patchprobe").map(|dirs| dirs.data_dir().to_path_buf())
}

/// Chemins des fichiers ; repli sur un dossier local si le dossier utilisateur est introuvable.
pub fn data_paths() -> DataPaths {
    DataPaths::new(data_dir().unwrap_or_else(|| std::env::temp_dir().join("PatchProbe")))
}
