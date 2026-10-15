//! Store en mémoire avec écritures disque débouncées : une rafale de modifications (frappe
//! clavier dans une note, centaines de noms mis en cache pendant un scan) donne UNE écriture
//! peu après la dernière modification, jamais une par changement.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::{mpsc, oneshot};

use super::file::{self, LoadStatus, StoreError};

pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(500);

enum Message {
    Changed,
    Flush(oneshot::Sender<()>),
}

/// Valeur partagée + écrivain en arrière-plan. Doit être créé dans un runtime tokio.
pub struct Store<T> {
    path: PathBuf,
    value: Arc<Mutex<T>>,
    last_error: Arc<Mutex<Option<StoreError>>>,
    tx: mpsc::UnboundedSender<Message>,
}

impl<T> Clone for Store<T> {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            value: Arc::clone(&self.value),
            last_error: Arc::clone(&self.last_error),
            tx: self.tx.clone(),
        }
    }
}

impl<T> Store<T>
where
    T: Serialize + DeserializeOwned + Default + Clone + Send + 'static,
{
    /// Charge `path` (voir [`file::load`]) et démarre l'écrivain débouncé.
    pub fn open(path: &Path, debounce: Duration) -> (Self, LoadStatus) {
        let (value, status) = file::load::<T>(path);
        (Self::with_value(path, value, debounce), status)
    }

    pub fn with_value(path: &Path, value: T, debounce: Duration) -> Self {
        let value = Arc::new(Mutex::new(value));
        let last_error = Arc::new(Mutex::new(None));
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(writer_loop(path.to_path_buf(), Arc::clone(&value), Arc::clone(&last_error), rx, debounce));
        Self { path: path.to_path_buf(), value, last_error, tx }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Copie de la valeur courante.
    pub fn get(&self) -> T {
        self.value.lock().map(|v| v.clone()).unwrap_or_default()
    }

    /// Lecture sans copie.
    pub fn read<R>(&self, f: impl FnOnce(&T) -> R) -> Option<R> {
        self.value.lock().ok().map(|v| f(&v))
    }

    /// Modifie la valeur et programme une écriture débouncée.
    pub fn update<R>(&self, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let result = self.value.lock().ok().map(|mut v| f(&mut v));
        let _ = self.tx.send(Message::Changed);
        result
    }

    /// Valeur partagée, pour un composant qui la modifie directement (ex. le cache de
    /// résolution utilisé par le résolveur) ; appeler [`Store::touch`] ensuite.
    pub fn shared(&self) -> Arc<Mutex<T>> {
        Arc::clone(&self.value)
    }

    /// Programme une écriture après une modification faite via [`Store::shared`].
    pub fn touch(&self) {
        let _ = self.tx.send(Message::Changed);
    }

    /// Dernière erreur d'écriture (disque plein, droits…), effacée au prochain succès.
    pub fn last_error(&self) -> Option<StoreError> {
        self.last_error.lock().ok().and_then(|e| e.clone())
    }

    /// Écrit immédiatement ce qui est en attente (fermeture de l'app).
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Message::Flush(ack)).is_ok() {
            let _ = done.await;
        }
    }
}

async fn write_snapshot<T: Serialize + Clone + Send + 'static>(
    path: &Path,
    value: &Arc<Mutex<T>>,
    last_error: &Arc<Mutex<Option<StoreError>>>,
) {
    let Some(bytes) = value.lock().ok().map(|v| file::encode(&*v)) else { return };
    let path = path.to_path_buf();
    let result = match bytes {
        Ok(bytes) => tokio::task::spawn_blocking(move || file::write_atomic(&path, &bytes))
            .await
            .unwrap_or_else(|e| Err(StoreError::Write { path: String::new(), message: e.to_string() })),
        Err(e) => Err(e),
    };
    if let Ok(mut slot) = last_error.lock() {
        *slot = result.err();
    }
}

async fn writer_loop<T: Serialize + Clone + Send + 'static>(
    path: PathBuf,
    value: Arc<Mutex<T>>,
    last_error: Arc<Mutex<Option<StoreError>>>,
    mut rx: mpsc::UnboundedReceiver<Message>,
    debounce: Duration,
) {
    let mut dirty = false;
    loop {
        let message = if dirty {
            match tokio::time::timeout(debounce, rx.recv()).await {
                Ok(message) => message,
                Err(_) => {
                    write_snapshot(&path, &value, &last_error).await;
                    dirty = false;
                    continue;
                }
            }
        } else {
            rx.recv().await
        };
        match message {
            Some(Message::Changed) => dirty = true,
            Some(Message::Flush(ack)) => {
                if dirty {
                    write_snapshot(&path, &value, &last_error).await;
                    dirty = false;
                }
                let _ = ack.send(());
            }
            None => {
                // Tous les `Store` ont été détruits : dernière écriture si nécessaire.
                if dirty {
                    write_snapshot(&path, &value, &last_error).await;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir()
            .join(format!("patchprobe-debounce-{tag}-{}-{:x}", std::process::id(), rand::random::<u32>()))
            .join("data.json")
    }

    #[tokio::test(start_paused = true)]
    async fn bursts_are_coalesced_into_one_write() {
        let path = temp_path("burst");
        let (store, status) = Store::<Vec<u32>>::open(&path, Duration::from_millis(500));
        assert_eq!(status, LoadStatus::Missing);
        for i in 0..100 {
            store.update(|v| v.push(i));
            tokio::time::sleep(Duration::from_millis(10)).await;
            assert!(!path.exists(), "aucune écriture pendant la rafale");
        }
        tokio::time::sleep(Duration::from_millis(600)).await;
        // L'écriture passe par spawn_blocking : on lui laisse le temps de finir.
        for _ in 0..1000 {
            if path.exists() {
                break;
            }
            tokio::time::advance(Duration::from_millis(10)).await;
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(5));
        }
        let (loaded, _) = file::load::<Vec<u32>>(&path);
        assert_eq!(loaded.len(), 100);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn flush_writes_immediately_and_reload_works() {
        let path = temp_path("flush");
        let (store, _) = Store::<Vec<String>>::open(&path, Duration::from_secs(3600));
        store.update(|v| v.push("note".into()));
        store.flush().await;
        assert!(store.last_error().is_none());
        let (reopened, status) = Store::<Vec<String>>::open(&path, Duration::from_secs(1));
        assert_eq!(status, LoadStatus::Loaded);
        assert_eq!(reopened.get(), ["note"]);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn write_failures_are_reported() {
        let base = temp_path("fail");
        fs::create_dir_all(base.parent().unwrap()).unwrap();
        fs::write(&base, b"je suis un fichier").unwrap();
        // Le parent du fichier cible est un fichier : écriture impossible.
        let (store, _) = Store::<Vec<u8>>::open(&base.join("child.json"), Duration::from_millis(1));
        store.update(|v| v.push(1));
        store.flush().await;
        assert!(store.last_error().is_some());
        fs::remove_dir_all(base.parent().unwrap()).unwrap();
    }
}
