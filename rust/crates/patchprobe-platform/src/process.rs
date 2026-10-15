//! Exécution de sous-processus : arguments toujours passés en tableau (jamais de shell),
//! processus tué si le délai expire, si l'opération est annulée ou si la future est abandonnée.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use thiserror::Error;
use tokio::process::Command;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub success: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RunError {
    #[error("programme introuvable : {0}")]
    NotFound(String),
    #[error("délai dépassé ({0} s) — processus arrêté")]
    Timeout(u64),
    #[error("opération annulée — processus arrêté")]
    Cancelled,
    #[error("échec du lancement : {0}")]
    Io(String),
}

/// Prépare une commande sans fenêtre console (Windows), stdin fermé, sorties capturées, tuée à
/// la destruction. Sous Unix, la locale est forcée à `C` pour des sorties stables.
pub fn command(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    #[cfg(unix)]
    cmd.env("LC_ALL", "C").env("LANG", "C");
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// Lance `program args…` et attend sa fin, au plus `timeout`, interruptible par `cancel`.
pub async fn run<I, S>(
    program: &Path,
    args: I,
    timeout: Duration,
    cancel: Option<&CancellationToken>,
) -> Result<CommandOutput, RunError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let child = command(program).args(args).spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            RunError::NotFound(program.display().to_string())
        } else {
            RunError::Io(e.to_string())
        }
    })?;
    // `wait_with_output` possède l'enfant : abandonner la future le détruit, et `kill_on_drop`
    // envoie alors SIGKILL / TerminateProcess.
    let output = child.wait_with_output();
    let never = CancellationToken::new();
    let cancel = cancel.unwrap_or(&never);
    tokio::select! {
        result = output => {
            let output = result.map_err(|e| RunError::Io(e.to_string()))?;
            Ok(CommandOutput {
                success: output.status.success(),
                code: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
        () = tokio::time::sleep(timeout) => Err(RunError::Timeout(timeout.as_secs())),
        () = cancel.cancelled() => Err(RunError::Cancelled),
    }
}

/// Cherche un exécutable dans le PATH puis dans des emplacements connus.
pub fn find_executable(name: &str, extra_dirs: &[&str]) -> Option<PathBuf> {
    let file_names: Vec<String> =
        if cfg!(windows) { vec![format!("{name}.exe"), name.to_owned()] } else { vec![name.to_owned()] };
    let path_dirs = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect::<Vec<_>>()).unwrap_or_default();
    path_dirs
        .into_iter()
        .chain(extra_dirs.iter().map(PathBuf::from))
        .flat_map(|dir| file_names.iter().map(move |f| dir.join(f)))
        .find(|candidate| is_executable(candidate))
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else { return false };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn sh() -> PathBuf {
        find_executable("sh", &["/bin"]).unwrap()
    }

    #[tokio::test]
    async fn captures_output_with_array_args() {
        // L'argument contient des métacaractères : il n'est jamais interprété par un shell.
        let out =
            run(&find_executable("echo", &["/bin"]).unwrap(), ["a; rm -rf /tmp/x $(id)"], Duration::from_secs(5), None)
                .await
                .unwrap();
        assert!(out.success);
        assert_eq!(out.stdout.trim(), "a; rm -rf /tmp/x $(id)");
    }

    #[tokio::test]
    async fn timeout_kills_the_child() {
        let started = Instant::now();
        let result = run(&sh(), ["-c", "sleep 30"], Duration::from_millis(200), None).await;
        assert_eq!(result, Err(RunError::Timeout(0)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn cancellation_kills_the_child() {
        let marker = std::env::temp_dir().join(format!("patchprobe-cancel-{}", std::process::id()));
        let _ = std::fs::remove_file(&marker);
        let cancel = CancellationToken::new();
        let script = format!("sleep 1; touch {}", marker.display());
        let task = {
            let cancel = cancel.clone();
            let sh = sh();
            tokio::spawn(async move { run(&sh, ["-c", script.as_str()], Duration::from_secs(30), Some(&cancel)).await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        assert_eq!(task.await.unwrap(), Err(RunError::Cancelled));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(!marker.exists(), "le processus aurait dû être tué avant de créer le fichier");
    }

    #[tokio::test]
    async fn missing_program() {
        let result = run(Path::new("/nonexistent/patchprobe-tool"), ["x"], Duration::from_secs(1), None).await;
        assert!(matches!(result, Err(RunError::NotFound(_))));
        assert!(find_executable("definitely-not-a-real-binary-patchprobe", &[]).is_none());
    }
}
