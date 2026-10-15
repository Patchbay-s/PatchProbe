//! NetBIOS Name Service, requête NBSTAT (RFC 1002) — port de `NBNSService.swift`.
#![deny(clippy::indexing_slicing)]

use super::{byte, sanitize_name, Parsed};

/// Requête NBSTAT pour le nom joker `*`.
pub fn build_nbstat_query(transaction_id: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(50);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    packet.push(0x20);
    // Encodage « half-ASCII » de « * » complété de NUL sur 16 octets (RFC 1002 §4.1).
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    for b in raw {
        packet.push(b'A' + (b >> 4));
        packet.push(b'A' + (b & 0x0F));
    }
    packet.push(0x00);
    packet.extend_from_slice(&[0x00, 0x21, 0x00, 0x01]);
    packet
}

/// Extrait le nom de machine d'une réponse NBSTAT. Si les entrées complètes (nom 15 octets +
/// suffixe + drapeaux) sont présentes, préfère le premier nom unique de type station (0x00) ou
/// serveur (0x20) ; sinon le premier nom.
pub fn parse_nbstat_response(data: &[u8]) -> Parsed {
    if data.len() <= 12 {
        return Parsed::Malformed("réponse NBNS trop courte");
    }
    let mut offset = 12;
    let Some(label_len) = byte(data, offset) else {
        return Parsed::Malformed("question absente");
    };
    offset += 1 + usize::from(label_len);
    if byte(data, offset) != Some(0) {
        return Parsed::Malformed("question NBNS illisible");
    }
    offset += 1 + 4;
    // Le NAME de la réponse est, dans toutes les réponses réelles, un pointeur de compression.
    match byte(data, offset) {
        Some(b) if b & 0xC0 == 0xC0 && byte(data, offset + 1).is_some() => offset += 2,
        _ => return Parsed::Malformed("nom de réponse NBNS inattendu"),
    }
    // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)
    offset += 10;
    if offset > data.len() {
        return Parsed::Malformed("enregistrement NBNS tronqué");
    }
    let Some(count) = byte(data, offset) else {
        return Parsed::Malformed("nombre de noms absent");
    };
    offset += 1;
    if count == 0 {
        return Parsed::NoName("la machine ne publie aucun nom NetBIOS");
    }
    let name_at = |index: usize| -> Option<(String, Option<u8>, Option<u16>)> {
        let start = offset + index * 18;
        let raw = data.get(start..start + 15)?;
        let name = String::from_utf8_lossy(raw).trim_end_matches([' ', '\0']).to_owned();
        let suffix = byte(data, start + 15);
        let flags = super::be16(data, start + 16);
        Some((name, suffix, flags))
    };
    let preferred = (0..usize::from(count)).filter_map(name_at).find(|(name, suffix, flags)| {
        let unique = flags.is_some_and(|f| f & 0x8000 == 0);
        unique && matches!(suffix, Some(0x00 | 0x20)) && !name.trim().is_empty()
    });
    match preferred.or_else(|| name_at(0)).and_then(|(name, _, _)| sanitize_name(&name)) {
        Some(name) => Parsed::Name(name),
        None if name_at(0).is_none() => Parsed::Malformed("table de noms tronquée"),
        None => Parsed::NoName("nom NetBIOS vide"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixture de la version Swift : nom de 15 octets seulement (sans suffixe ni drapeaux).
    fn swift_fixture(name: &str, num_names: u8) -> Vec<u8> {
        let mut p = vec![0u8; 12];
        p.push(32);
        p.extend(std::iter::repeat_n(b'A', 32));
        p.push(0);
        p.extend_from_slice(&[0, 0x21, 0, 1, 0xC0, 0x0C, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0]);
        p.push(num_names);
        if num_names > 0 {
            p.extend(format!("{name:<15}").bytes());
        }
        p
    }

    /// Réponse complète capturée sur un PC Windows (groupe WORKGROUP puis nom unique).
    fn full_response() -> Vec<u8> {
        let mut p = swift_fixture("", 0);
        let last = p.len() - 1;
        p[last] = 3;
        for (name, suffix, flags) in
            [("WORKGROUP", 0x00u8, 0x8400u16), ("TEST-PC", 0x20, 0x0400), ("TEST-PC", 0x00, 0x0400)]
        {
            p.extend(format!("{name:<15}").bytes());
            p.push(suffix);
            p.extend_from_slice(&flags.to_be_bytes());
        }
        p.extend_from_slice(&[0x00, 0x15, 0x5D, 0x01, 0x02, 0x03]);
        p
    }

    #[test]
    fn swift_vectors() {
        assert_eq!(parse_nbstat_response(&swift_fixture("TESTHOST", 1)), Parsed::Name("TESTHOST".into()));
        assert_eq!(parse_nbstat_response(&swift_fixture("PC", 1)), Parsed::Name("PC".into()));
        assert!(matches!(parse_nbstat_response(&[0; 5]), Parsed::Malformed(_)));
        assert!(matches!(parse_nbstat_response(&swift_fixture("TESTHOST", 0)), Parsed::NoName(_)));
        let mut no_pointer = swift_fixture("TESTHOST", 1);
        no_pointer[12 + 1 + 32 + 1 + 4] = 0;
        assert!(matches!(parse_nbstat_response(&no_pointer), Parsed::Malformed(_)));
    }

    #[test]
    fn skips_group_names() {
        assert_eq!(parse_nbstat_response(&full_response()), Parsed::Name("TEST-PC".into()));
    }

    #[test]
    fn query_shape() {
        let q = build_nbstat_query(0x1234);
        assert_eq!(q.len(), 50);
        assert_eq!(&q[13..15], b"CK");
        assert_eq!(&q[q.len() - 4..], &[0, 0x21, 0, 1]);
    }

    #[test]
    fn truncations_never_panic() {
        let full = full_response();
        for len in 0..full.len() {
            let _ = parse_nbstat_response(&full[..len]);
        }
    }
}
