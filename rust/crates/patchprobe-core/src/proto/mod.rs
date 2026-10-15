//! Encodeurs/décodeurs de protocoles, faits main et bornés : aucun indexage direct, aucun
//! panic sur un paquet malformé (lint `indexing_slicing` actif dans chaque module).

pub mod dns;
pub mod http_title;
pub mod nbns;
pub mod smb;
pub mod snmp;
pub mod ssdp;

/// Résultat du décodage d'une réponse portant un nom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Name(String),
    /// Réponse valide mais sans nom (NXDOMAIN, 0 réponse, liste vide…).
    NoName(&'static str),
    /// Paquet malformé ou inattendu.
    Malformed(&'static str),
}

/// Lecture bornée d'octets.
pub(crate) fn byte(data: &[u8], offset: usize) -> Option<u8> {
    data.get(offset).copied()
}

pub(crate) fn be16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

pub(crate) fn le16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([*bytes.first()?, *bytes.get(1)?]))
}

pub(crate) fn le32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Nettoie un nom reçu du réseau : caractères de contrôle retirés, espaces bordants supprimés,
/// longueur bornée. `None` si rien d'utile ne reste.
pub fn sanitize_name(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).take(253).collect();
    let trimmed = cleaned.trim().trim_end_matches('.').trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_readers() {
        assert_eq!(be16(&[1, 2], 0), Some(0x0102));
        assert_eq!(be16(&[1], 0), None);
        assert_eq!(be16(&[1, 2], usize::MAX), None);
        assert_eq!(le32(&[1, 0, 0, 0], 0), Some(1));
        assert_eq!(le32(&[1, 0, 0], 0), None);
    }

    #[test]
    fn sanitizes_names() {
        assert_eq!(sanitize_name(" storage.example.invalid. ").as_deref(), Some("storage.example.invalid"));
        assert_eq!(sanitize_name("a\u{0}b\n").as_deref(), Some("ab"));
        assert_eq!(sanitize_name(" \u{7} "), None);
    }
}
