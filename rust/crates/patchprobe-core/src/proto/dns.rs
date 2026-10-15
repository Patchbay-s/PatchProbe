//! Messages DNS minimalistes (RFC 1035) : requête PTR inverse et lecture de la réponse.
//! Partagés par le DNS de la passerelle, LLMNR (RFC 4795) et mDNS unicast — port de
//! `LLMNRService.buildQuery/parseResponse/decodeName`, durci (plusieurs questions/réponses,
//! code de retour, identifiant de transaction).
#![deny(clippy::indexing_slicing)]

use std::net::Ipv4Addr;

use super::{be16, byte, sanitize_name, Parsed};

pub const TYPE_PTR: u16 = 12;
const CLASS_IN: u16 = 1;
const MAX_POINTER_JUMPS: usize = 128;

/// `203.0.113.192.in-addr.arpa` pour `192.0.2.10`.
pub fn reverse_name(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// Requête PTR (QTYPE 12, QCLASS IN) pour l'adresse inverse de `ip`.
pub fn build_ptr_query(ip: Ipv4Addr, transaction_id: u16, recursion_desired: bool) -> Vec<u8> {
    let mut packet = Vec::with_capacity(48);
    packet.extend_from_slice(&transaction_id.to_be_bytes());
    packet.extend_from_slice(if recursion_desired { &[0x01, 0x00] } else { &[0x00, 0x00] });
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in reverse_name(ip).split('.') {
        // Labels d'au plus 15 octets ici : la conversion ne peut pas échouer.
        packet.push(u8::try_from(label.len()).unwrap_or(0));
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&TYPE_PTR.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    packet
}

/// Sonde DNS générique (NS de la racine, récursion demandée) utilisée par le scan UDP.
pub fn root_ns_query() -> Vec<u8> {
    vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x02, 0x00, 0x01]
}

/// Décode un nom DNS à `start`, en suivant les pointeurs de compression (RFC 1035 §4.1.4).
/// Renvoie le nom et la position juste après lui dans la lecture d'origine.
pub fn decode_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut offset = start;
    let mut next_offset: Option<usize> = None;
    let mut jumps = 0;
    let mut total_len = 0usize;
    loop {
        let length = byte(data, offset)?;
        if length == 0 {
            let after = next_offset.unwrap_or(offset + 1);
            return Some((labels.join("."), after));
        }
        if length & 0xC0 == 0xC0 {
            let low = byte(data, offset + 1)?;
            jumps += 1;
            if jumps > MAX_POINTER_JUMPS {
                return None;
            }
            if next_offset.is_none() {
                next_offset = Some(offset + 2);
            }
            offset = usize::from(length & 0x3F) << 8 | usize::from(low);
            continue;
        }
        if length & 0xC0 != 0 {
            return None; // types de label réservés
        }
        let len = usize::from(length);
        let label = data.get(offset + 1..offset + 1 + len)?;
        total_len += len + 1;
        if total_len > 255 {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        offset += 1 + len;
    }
}

/// Lit la première réponse PTR. Si `expected_id` est fourni, l'identifiant de transaction doit
/// correspondre (réponse à une autre requête sinon).
pub fn parse_ptr_response(data: &[u8], expected_id: Option<u16>) -> Parsed {
    let (Some(id), Some(flags), Some(qdcount), Some(ancount)) =
        (be16(data, 0), be16(data, 2), be16(data, 4), be16(data, 6))
    else {
        return Parsed::Malformed("en-tête DNS tronqué");
    };
    if expected_id.is_some_and(|expected| expected != id) {
        return Parsed::Malformed("identifiant de transaction inattendu");
    }
    if flags & 0x8000 == 0 {
        return Parsed::Malformed("le paquet n'est pas une réponse");
    }
    match flags & 0x000F {
        0 => {}
        3 => return Parsed::NoName("NXDOMAIN (aucun enregistrement PTR)"),
        2 => return Parsed::NoName("SERVFAIL"),
        5 => return Parsed::NoName("requête refusée (REFUSED)"),
        _ => return Parsed::NoName("code de réponse DNS en erreur"),
    }
    if ancount == 0 {
        return Parsed::NoName("aucune réponse dans le paquet");
    }
    let mut offset = 12;
    for _ in 0..qdcount {
        let Some((_, after)) = decode_name(data, offset) else {
            return Parsed::Malformed("question illisible");
        };
        offset = after + 4;
    }
    for _ in 0..ancount {
        let Some((_, after)) = decode_name(data, offset) else {
            return Parsed::Malformed("nom de réponse illisible");
        };
        let (Some(rtype), Some(rdlength)) = (be16(data, after), be16(data, after + 8)) else {
            return Parsed::Malformed("enregistrement tronqué");
        };
        let rdata_start = after + 10;
        let rdata_end = rdata_start + usize::from(rdlength);
        if rdata_end > data.len() {
            return Parsed::Malformed("RDATA hors du paquet");
        }
        if rtype == TYPE_PTR {
            return match decode_name(data, rdata_start).and_then(|(name, _)| sanitize_name(&name)) {
                Some(name) => Parsed::Name(name),
                None => Parsed::Malformed("RDATA PTR illisible"),
            };
        }
        offset = rdata_end;
    }
    Parsed::NoName("aucun enregistrement PTR parmi les réponses")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_name(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(u8::try_from(label.len()).unwrap());
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    /// Réponse PTR réaliste : question recopiée, réponse avec pointeur vers la question.
    fn ptr_response(id: u16, ip: Ipv4Addr, answer: &str, rcode: u8) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&[0x84, rcode]);
        p.extend_from_slice(&[0, 1, 0, u8::from(rcode == 0), 0, 0, 0, 0]);
        p.extend(encode_name(&reverse_name(ip)));
        p.extend_from_slice(&[0, 12, 0, 1]);
        if rcode == 0 {
            p.extend_from_slice(&[0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 120]);
            let rdata = encode_name(answer);
            p.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
            p.extend(rdata);
        }
        p
    }

    #[test]
    fn query_reverses_octets() {
        let q = build_ptr_query(Ipv4Addr::new(192, 0, 2, 10), 0xABCD, false);
        assert_eq!(&q[..2], &[0xAB, 0xCD]);
        let text: String = q[12..].iter().map(|b| if b.is_ascii_graphic() { *b as char } else { '.' }).collect();
        assert!(text.contains("10") && text.contains("in-addr") && text.contains("arpa"));
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x0C, 0x00, 0x01]);
        assert_eq!(decode_name(&q, 12).unwrap().0, "10.2.0.192.in-addr.arpa");
    }

    #[test]
    fn decode_plain_and_compressed() {
        let mut p = vec![0u8; 12];
        p.extend(encode_name("abc.local"));
        assert_eq!(decode_name(&p, 12), Some(("abc.local".into(), p.len())));

        let mut p = vec![0u8; 12];
        p.extend(encode_name("host"));
        let pointer_offset = p.len();
        p.extend_from_slice(&[0xC0, 12]);
        assert_eq!(decode_name(&p, pointer_offset), Some(("host".into(), pointer_offset + 2)));
    }

    #[test]
    fn decode_rejects_loops_and_truncation() {
        assert_eq!(decode_name(&[0xC0, 0x00], 0), None);
        assert_eq!(decode_name(&[5, b'a', b'b'], 0), None);
        assert_eq!(decode_name(&[], 0), None);
        assert_eq!(decode_name(&[0x40], 0), None);
    }

    #[test]
    fn parses_ptr_response() {
        let ip = Ipv4Addr::new(192, 0, 2, 10);
        let response = ptr_response(7, ip, "storage.example.invalid", 0);
        assert_eq!(parse_ptr_response(&response, Some(7)), Parsed::Name("storage.example.invalid".into()));
        assert!(matches!(parse_ptr_response(&response, Some(8)), Parsed::Malformed(_)));
        assert!(matches!(parse_ptr_response(&ptr_response(7, ip, "", 3), None), Parsed::NoName(_)));
    }

    #[test]
    fn rejects_zero_answers_and_garbage() {
        let mut header = vec![0u8; 12];
        header[2] = 0x80;
        assert!(matches!(parse_ptr_response(&header, None), Parsed::NoName(_)));
        assert!(matches!(parse_ptr_response(&[1, 2, 3], None), Parsed::Malformed(_)));
        let query = build_ptr_query(Ipv4Addr::LOCALHOST, 1, false);
        assert!(matches!(parse_ptr_response(&query, None), Parsed::Malformed(_)));
    }

    #[test]
    fn truncated_responses_never_panic() {
        let response = ptr_response(7, Ipv4Addr::new(198, 51, 100, 1), "printer.example.invalid", 0);
        for len in 0..response.len() {
            let _ = parse_ptr_response(&response[..len], None);
        }
        // Octets aléatoires.
        for seed in 0u32..2000 {
            let bytes: Vec<u8> = (0..(seed % 80))
                .map(|i| (seed.wrapping_mul(2_654_435_761).wrapping_add(i * 97) >> 7).to_le_bytes()[0])
                .collect();
            let _ = parse_ptr_response(&bytes, None);
        }
    }

    #[test]
    fn root_ns_query_shape() {
        let p = root_ns_query();
        assert_eq!(p.len(), 17);
        assert_eq!(&p[4..6], &[0, 1]);
        assert_eq!(&p[13..15], &[0, 2]);
    }
}
