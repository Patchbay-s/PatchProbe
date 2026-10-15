//! Plafond global de connexions TCP simultanées, instrumenté (pic observé) pour les tests et
//! le diagnostic.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug)]
pub struct ConnectionLimiter {
    semaphore: Arc<Semaphore>,
    capacity: usize,
    in_flight: AtomicUsize,
    peak: AtomicUsize,
}

/// Jeton d'une connexion en vol ; libère la place à la destruction.
#[derive(Debug)]
pub struct ConnectionPermit {
    limiter: Arc<ConnectionLimiter>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.limiter.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

impl ConnectionLimiter {
    pub fn new(capacity: usize) -> Arc<Self> {
        let capacity = capacity.max(1);
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
            capacity,
            in_flight: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }

    /// Attend une place libre. `None` seulement si le sémaphore a été fermé.
    pub async fn acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let permit = Arc::clone(&self.semaphore).acquire_owned().await.ok()?;
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        Some(ConnectionPermit { limiter: Arc::clone(self), _permit: permit })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn in_flight(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Nombre maximal de connexions simultanées observé depuis la création.
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_in_flight_and_peak() {
        let limiter = ConnectionLimiter::new(2);
        let a = limiter.acquire().await.unwrap();
        let b = limiter.acquire().await.unwrap();
        assert_eq!(limiter.in_flight(), 2);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(20), limiter.acquire()).await.is_err());
        drop(a);
        let _c = limiter.acquire().await.unwrap();
        drop(b);
        assert_eq!(limiter.in_flight(), 1);
        assert_eq!(limiter.peak(), 2);
    }
}
