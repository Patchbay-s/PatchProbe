//! Outils d'analyse par hôte : nmap et traceroute/tracert.

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use patchprobe_core::parsers::nmap::{parse_nmap_xml, NmapReport};
use patchprobe_core::parsers::traceroute::{parse_traceroute, TracerouteHop};
use serde::Serialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::process::{find_executable, run, RunError};

/// Durée maximale d'un scan nmap (comme la version Swift).
pub const NMAP_MAX_DURATION: Duration = Duration::from_secs(45);

#[cfg(target_os = "macos")]
const NMAP_DIRS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/usr/bin"];
#[cfg(target_os = "windows")]
const NMAP_DIRS: &[&str] = &["C:\\Program Files (x86)\\Nmap", "C:\\Program Files\\Nmap"];
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
const NMAP_DIRS: &[&str] = &["/usr/bin", "/usr/local/bin", "/snap/bin"];

/// Indication d'installation propre à l'OS.
pub fn nmap_install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "nmap introuvable — installez-le avec « brew install nmap »."
    } else if cfg!(target_os = "windows") {
        "nmap introuvable — installez-le depuis https://nmap.org/download.html (installateur Windows)."
    } else {
        "nmap introuvable — installez-le avec le gestionnaire de paquets (ex. « sudo apt install nmap »)."
    }
}

pub fn find_nmap() -> Option<PathBuf> {
    find_executable("nmap", NMAP_DIRS)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ToolError {
    #[error("{0}")]
    NotInstalled(String),
    #[error("{0}")]
    Run(#[from] RunError),
    #[error("{0}")]
    Failed(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NmapResult {
    pub report: NmapReport,
    /// Sortie brute, affichée quand le XML n'a donné aucun port.
    pub raw_output: String,
    pub command_line: String,
}

/// Arguments nmap : toujours `-Pn` (pas de ping préalable, l'hôte est connu vivant) et `-sV`.
pub fn nmap_args(ip: Ipv4Addr) -> Vec<String> {
    ["-Pn", "-sV", "-T4", "--version-intensity", "2", "-oX", "-"]
        .into_iter()
        .map(str::to_owned)
        .chain(std::iter::once(ip.to_string()))
        .collect()
}

pub async fn run_nmap(ip: Ipv4Addr, cancel: &CancellationToken) -> Result<NmapResult, ToolError> {
    let path = find_nmap().ok_or_else(|| ToolError::NotInstalled(nmap_install_hint().to_owned()))?;
    let args = nmap_args(ip);
    let output = run(&path, &args, NMAP_MAX_DURATION, Some(cancel)).await?;
    let report = parse_nmap_xml(&output.stdout);
    if !output.success && report.ports.is_empty() {
        let detail = if output.stderr.trim().is_empty() { output.stdout.trim() } else { output.stderr.trim() };
        let code = output.code.map_or_else(|| "?".to_owned(), |c| c.to_string());
        return Err(ToolError::Failed(format!("nmap a quitté avec le code {code} : {detail}")));
    }
    Ok(NmapResult { report, raw_output: output.stdout, command_line: format!("nmap {}", args.join(" ")) })
}

/// Commande traceroute de l'OS courant (`tracert` sous Windows, `traceroute` ou `tracepath`
/// ailleurs), ou `None` si aucune n'est disponible.
pub fn traceroute_command(ip: Ipv4Addr) -> Option<(PathBuf, Vec<String>, Duration)> {
    let target = ip.to_string();
    if cfg!(target_os = "windows") {
        let path = find_executable("tracert", &["C:\\Windows\\System32"])?;
        let args = ["-d", "-h", "30", "-w", "1000", target.as_str()].map(str::to_owned).to_vec();
        return Some((path, args, Duration::from_secs(120)));
    }
    if let Some(path) = find_executable("traceroute", &["/usr/sbin", "/usr/bin", "/sbin"]) {
        let args = ["-n", "-q", "1", "-w", "1", "-m", "30", target.as_str()].map(str::to_owned).to_vec();
        return Some((path, args, Duration::from_secs(45)));
    }
    let path = find_executable("tracepath", &["/usr/bin", "/usr/sbin", "/bin"])?;
    Some((path, vec!["-n".to_owned(), target], Duration::from_secs(45)))
}

pub async fn run_traceroute(ip: Ipv4Addr, cancel: &CancellationToken) -> Result<Vec<TracerouteHop>, ToolError> {
    let (path, args, timeout) = traceroute_command(ip).ok_or_else(|| {
        ToolError::NotInstalled(
            "traceroute introuvable sur ce système (ni traceroute, ni tracepath, ni tracert).".into(),
        )
    })?;
    let output = run(&path, &args, timeout, Some(cancel)).await?;
    let hops = parse_traceroute(&output.stdout);
    if hops.is_empty() {
        let detail = if output.stderr.trim().is_empty() { "aucun saut dans la sortie" } else { output.stderr.trim() };
        return Err(ToolError::Failed(format!("échec du traceroute : {detail}")));
    }
    Ok(hops)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_args_always_include_pn_and_sv() {
        let args = nmap_args(Ipv4Addr::new(192, 0, 2, 10));
        assert!(args.contains(&"-Pn".to_owned()));
        assert!(args.contains(&"-sV".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("192.0.2.10"));
        let joined = args.join(" ");
        assert!(joined.contains("-oX -"));
    }

    #[tokio::test]
    async fn missing_nmap_gives_clear_message() {
        if find_nmap().is_some() {
            return; // nmap installé sur cette machine : rien à vérifier ici
        }
        let err = run_nmap(Ipv4Addr::LOCALHOST, &CancellationToken::new()).await.unwrap_err();
        assert!(matches!(err, ToolError::NotInstalled(ref m) if m.contains("nmap introuvable")));
    }
}
