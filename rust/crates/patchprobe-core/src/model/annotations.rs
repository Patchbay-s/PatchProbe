//! Favoris et notes libres par IP — port de `FavoritesStore.swift`.
//!
//! Différence volontaire : une note ne rend plus l'IP favorite d'office (les deux sont
//! indépendants) ; une entrée sans favori ni note est supprimée.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Longueur maximale d'une note (caractères).
pub const MAX_NOTE_CHARS: usize = 4000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpAnnotation {
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub note: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Annotations {
    entries: BTreeMap<Ipv4Addr, IpAnnotation>,
}

impl Annotations {
    pub fn get(&self, ip: Ipv4Addr) -> Option<&IpAnnotation> {
        self.entries.get(&ip)
    }

    pub fn is_favorite(&self, ip: Ipv4Addr) -> bool {
        self.entries.get(&ip).is_some_and(|a| a.favorite)
    }

    pub fn note(&self, ip: Ipv4Addr) -> &str {
        self.entries.get(&ip).map_or("", |a| a.note.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Ipv4Addr, &IpAnnotation)> {
        self.entries.iter()
    }

    fn update(&mut self, ip: Ipv4Addr, now: DateTime<Utc>, change: impl FnOnce(&mut IpAnnotation)) {
        let entry = self.entries.entry(ip).or_insert_with(|| IpAnnotation {
            favorite: false,
            note: String::new(),
            updated_at: now,
        });
        change(entry);
        entry.updated_at = now;
        if !entry.favorite && entry.note.trim().is_empty() {
            self.entries.remove(&ip);
        }
    }

    pub fn set_favorite(&mut self, ip: Ipv4Addr, favorite: bool, now: DateTime<Utc>) {
        self.update(ip, now, |a| a.favorite = favorite);
    }

    pub fn toggle_favorite(&mut self, ip: Ipv4Addr, now: DateTime<Utc>) -> bool {
        let favorite = !self.is_favorite(ip);
        self.set_favorite(ip, favorite, now);
        favorite
    }

    pub fn set_note(&mut self, ip: Ipv4Addr, note: &str, now: DateTime<Utc>) {
        let note: String = note.chars().take(MAX_NOTE_CHARS).collect();
        self.update(ip, now, |a| a.note = note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);

    #[test]
    fn favorite_and_note_are_independent() {
        let mut a = Annotations::default();
        assert!(!a.is_favorite(IP));
        assert!(a.toggle_favorite(IP, Utc::now()));
        a.set_note(IP, "Test printer", Utc::now());
        assert!(!a.toggle_favorite(IP, Utc::now()));
        assert_eq!(a.note(IP), "Test printer");
        a.set_note(IP, "  ", Utc::now());
        assert!(a.get(IP).is_none(), "entrée vide supprimée");
    }

    #[test]
    fn note_is_bounded_and_serializes_as_map() {
        let mut a = Annotations::default();
        a.set_note(IP, &"x".repeat(10_000), Utc::now());
        assert_eq!(a.note(IP).len(), MAX_NOTE_CHARS);
        let json = serde_json::to_value(&a).unwrap();
        assert!(json.get("192.0.2.10").is_some());
        let back: Annotations = serde_json::from_value(json).unwrap();
        assert_eq!(back, a);
    }
}
