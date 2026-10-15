//! SNMPv1 GetRequest/GetResponse en BER/ASN.1 fait main — port de `SNMPService.swift`.
//!
//! Le décodage est borné : longueurs longues limitées à 4 octets, chaque TLV vérifié contre la
//! taille du tampon, profondeur fixe. Aucun panic possible sur un tampon malformé.
#![deny(clippy::indexing_slicing)]

use serde::{Deserialize, Serialize};

pub const OID_SYS_DESCR: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
pub const OID_SYS_UPTIME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 3, 0];
pub const OID_SYS_CONTACT: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 4, 0];
pub const OID_SYS_NAME: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 5, 0];
pub const OID_SYS_LOCATION: &[u32] = &[1, 3, 6, 1, 2, 1, 1, 6, 0];
pub const OID_IF_NUMBER: &[u32] = &[1, 3, 6, 1, 2, 1, 2, 1, 0];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GET_REQUEST: u8 = 0xA0;
const TAG_GET_RESPONSE: u8 = 0xA2;
const TAG_COUNTER32: u8 = 0x41;
const TAG_GAUGE32: u8 = 0x42;
const TAG_TIMETICKS: u8 = 0x43;
const TAG_COUNTER64: u8 = 0x46;

// ---------------------------------------------------------------- encodage

fn ber_length(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![u8::try_from(length).unwrap_or(0)];
    }
    let bytes: Vec<u8> = length.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap_or(0)];
    out.extend(bytes);
    out
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(ber_length(value.len()));
    out.extend_from_slice(value);
    out
}

fn ber_integer(value: u32) -> Vec<u8> {
    let mut bytes: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes.first().is_some_and(|b| b & 0x80 != 0) {
        bytes.insert(0, 0); // reste positif sans ambiguïté
    }
    tlv(TAG_INTEGER, &bytes)
}

fn base128(value: u32) -> Vec<u8> {
    let mut septets = vec![u8::try_from(value & 0x7F).unwrap_or(0)];
    let mut v = value >> 7;
    while v > 0 {
        septets.insert(0, u8::try_from(v & 0x7F).unwrap_or(0) | 0x80);
        v >>= 7;
    }
    septets
}

fn ber_oid(arcs: &[u32]) -> Vec<u8> {
    let (Some(first), Some(second)) = (arcs.first(), arcs.get(1)) else {
        return tlv(TAG_OID, &[]);
    };
    let mut bytes = base128(first.saturating_mul(40).saturating_add(*second));
    for arc in arcs.iter().skip(2) {
        bytes.extend(base128(*arc));
    }
    tlv(TAG_OID, &bytes)
}

/// GetRequest SNMPv1 pour un OID.
pub fn build_get_request(oid: &[u32], community: &str, request_id: u32) -> Vec<u8> {
    let mut varbind = ber_oid(oid);
    varbind.extend_from_slice(&[TAG_NULL, 0x00]);
    let varbind_list = tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &varbind));
    let mut pdu = ber_integer(request_id);
    pdu.extend(ber_integer(0));
    pdu.extend(ber_integer(0));
    pdu.extend(varbind_list);
    let mut message = ber_integer(0); // version 0 = SNMPv1
    message.extend(tlv(TAG_OCTET_STRING, community.as_bytes()));
    message.extend(tlv(TAG_GET_REQUEST, &pdu));
    tlv(TAG_SEQUENCE, &message)
}

// ---------------------------------------------------------------- décodage

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Tlv {
    tag: u8,
    start: usize,
    end: usize,
}

/// Lit un TLV à `offset` ; renvoie le TLV et la position suivante.
fn read_tlv(data: &[u8], offset: usize) -> Option<(Tlv, usize)> {
    let tag = *data.get(offset)?;
    let first = *data.get(offset + 1)?;
    let mut cursor = offset + 2;
    let length = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(cursor..cursor + count)?;
        cursor += count;
        bytes.iter().fold(0usize, |acc, b| acc << 8 | usize::from(*b))
    };
    let end = cursor.checked_add(length)?;
    if end > data.len() {
        return None;
    }
    Some((Tlv { tag, start: cursor, end }, end))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpValue {
    OctetString(Vec<u8>),
    Integer(i64),
    /// Counter32, Gauge32, TimeTicks, Counter64.
    Unsigned(u64),
    /// NULL, noSuchObject, noSuchInstance, endOfMibView, ou type non géré.
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnmpError {
    Malformed(&'static str),
    /// error-status non nul (ex. 2 = noSuchName en SNMPv1).
    AgentError(u32),
}

impl std::fmt::Display for SnmpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "réponse SNMP malformée : {why}"),
            Self::AgentError(2) => write!(f, "l'agent ne connaît pas cet OID (noSuchName)"),
            Self::AgentError(code) => write!(f, "erreur de l'agent SNMP (error-status {code})"),
        }
    }
}

fn read_unsigned(data: &[u8], tlv: Tlv) -> Option<u64> {
    let bytes = data.get(tlv.start..tlv.end)?;
    if bytes.is_empty() || bytes.len() > 9 || (bytes.len() == 9 && bytes.first() != Some(&0)) {
        return None;
    }
    Some(bytes.iter().fold(0u64, |acc, b| acc << 8 | u64::from(*b)))
}

fn read_signed(data: &[u8], tlv: Tlv) -> Option<i64> {
    let bytes = data.get(tlv.start..tlv.end)?;
    if bytes.is_empty() || bytes.len() > 8 {
        return None;
    }
    let negative = bytes.first().is_some_and(|b| b & 0x80 != 0);
    let init: i64 = if negative { -1 } else { 0 };
    Some(bytes.iter().fold(init, |acc, b| acc << 8 | i64::from(*b)))
}

/// Décode une GetResponse et renvoie (identifiant de requête, valeur du premier varbind).
pub fn parse_get_response(data: &[u8]) -> Result<(u32, SnmpValue), SnmpError> {
    use SnmpError::Malformed as M;
    let (message, _) = read_tlv(data, 0).filter(|(t, _)| t.tag == TAG_SEQUENCE).ok_or(M("message"))?;
    let (_version, next) = read_tlv(data, message.start).ok_or(M("version"))?;
    let (_community, next) = read_tlv(data, next).ok_or(M("community"))?;
    let (pdu, _) = read_tlv(data, next).ok_or(M("PDU"))?;
    if pdu.tag != TAG_GET_RESPONSE {
        return Err(M("PDU qui n'est pas une GetResponse"));
    }
    let (request_id, next) = read_tlv(data, pdu.start).ok_or(M("request-id"))?;
    let request_id = read_unsigned(data, request_id).and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
    let (error_status, next) = read_tlv(data, next).ok_or(M("error-status"))?;
    let (_error_index, next) = read_tlv(data, next).ok_or(M("error-index"))?;
    let status = read_unsigned(data, error_status).and_then(|v| u32::try_from(v).ok()).unwrap_or(0);
    if status != 0 {
        return Err(SnmpError::AgentError(status));
    }
    let (list, _) = read_tlv(data, next).filter(|(t, _)| t.tag == TAG_SEQUENCE).ok_or(M("varbind list"))?;
    let (varbind, _) = read_tlv(data, list.start).filter(|(t, _)| t.tag == TAG_SEQUENCE).ok_or(M("varbind"))?;
    let (_oid, next) = read_tlv(data, varbind.start).filter(|(t, _)| t.tag == TAG_OID).ok_or(M("OID"))?;
    let (value, _) = read_tlv(data, next).filter(|(t, _)| t.end <= varbind.end).ok_or(M("valeur"))?;
    let decoded = match value.tag {
        TAG_OCTET_STRING => SnmpValue::OctetString(data.get(value.start..value.end).unwrap_or_default().to_vec()),
        TAG_INTEGER => SnmpValue::Integer(read_signed(data, value).ok_or(M("entier"))?),
        TAG_COUNTER32 | TAG_GAUGE32 | TAG_TIMETICKS | TAG_COUNTER64 => {
            SnmpValue::Unsigned(read_unsigned(data, value).ok_or(M("entier non signé"))?)
        }
        other => SnmpValue::Other(other),
    };
    Ok((request_id, decoded))
}

/// Valeur texte (OCTET STRING non vide), décodée en UTF-8 avec remplacement.
pub fn extract_string(data: &[u8]) -> Option<String> {
    match parse_get_response(data) {
        Ok((_, SnmpValue::OctetString(bytes))) if !bytes.is_empty() => {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// Valeur entière positive (INTEGER, Counter, Gauge, TimeTicks).
pub fn extract_integer(data: &[u8]) -> Option<u64> {
    match parse_get_response(data) {
        Ok((_, SnmpValue::Unsigned(v))) => Some(v),
        Ok((_, SnmpValue::Integer(v))) => u64::try_from(v).ok(),
        _ => None,
    }
}

/// Uptime lisible à partir de centièmes de seconde : « 1 j 1 h », « 1 h 1 min », « 0 min ».
pub fn format_uptime(ticks: u64) -> String {
    let total_seconds = ticks / 100;
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let mut parts = Vec::new();
    if days > 0 {
        parts.push(format!("{days} j"));
    }
    if hours > 0 {
        parts.push(format!("{hours} h"));
    }
    if parts.is_empty() || minutes > 0 {
        parts.push(format!("{minutes} min"));
    }
    parts.join(" ")
}

/// Résultat du « walk » système (groupe MIB-II system).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnmpSystemInfo {
    pub sys_descr: Option<String>,
    pub sys_up_time: Option<String>,
    pub sys_contact: Option<String>,
    pub sys_name: Option<String>,
    pub sys_location: Option<String>,
    pub if_number: Option<u64>,
}

impl SnmpSystemInfo {
    pub fn is_empty(&self) -> bool {
        self.sys_descr.is_none()
            && self.sys_up_time.is_none()
            && self.sys_contact.is_none()
            && self.sys_name.is_none()
            && self.sys_location.is_none()
            && self.if_number.is_none()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Réponse GetResponse factice construite comme le ferait un agent réel.
    pub(crate) fn fake_response(oid: &[u32], value_tag: u8, value: &[u8]) -> Vec<u8> {
        let mut varbind = ber_oid(oid);
        varbind.extend(tlv(value_tag, value));
        let list = tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &varbind));
        let mut pdu = ber_integer(1);
        pdu.extend(ber_integer(0));
        pdu.extend(ber_integer(0));
        pdu.extend(list);
        let mut message = ber_integer(0);
        message.extend(tlv(TAG_OCTET_STRING, b"public"));
        message.extend(tlv(TAG_GET_RESPONSE, &pdu));
        tlv(TAG_SEQUENCE, &message)
    }

    fn integer_bytes(value: u64) -> Vec<u8> {
        let mut bytes: Vec<u8> = value.to_be_bytes().into_iter().skip_while(|b| *b == 0).collect();
        if bytes.first().is_none_or(|b| b & 0x80 != 0) {
            bytes.insert(0, 0);
        }
        bytes
    }

    #[test]
    fn extracts_sys_name() {
        let response = fake_response(OID_SYS_NAME, TAG_OCTET_STRING, b"TestRouter-42");
        assert_eq!(extract_string(&response).as_deref(), Some("TestRouter-42"));
    }

    #[test]
    fn rejects_truncated_and_garbage() {
        let mut response = fake_response(OID_SYS_NAME, TAG_OCTET_STRING, b"TestRouter-42");
        response.truncate(response.len() - 10);
        assert_eq!(extract_string(&response), None);
        assert_eq!(extract_string(&[0xFF, 0x00, 0x01]), None);
        assert_eq!(extract_string(&[]), None);
    }

    #[test]
    fn integers_and_timeticks() {
        assert_eq!(extract_integer(&fake_response(OID_IF_NUMBER, TAG_INTEGER, &integer_bytes(42))), Some(42));
        assert_eq!(
            extract_integer(&fake_response(OID_SYS_UPTIME, TAG_TIMETICKS, &integer_bytes(123_456))),
            Some(123_456)
        );
        assert_eq!(
            extract_integer(&fake_response(OID_SYS_UPTIME, TAG_TIMETICKS, &[0xFF, 0xFF, 0xFF, 0xFF])),
            Some(0xFFFF_FFFF)
        );
        assert_eq!(extract_integer(&fake_response(OID_SYS_NAME, TAG_OCTET_STRING, b"not-a-number")), None);
        assert_eq!(extract_string(&fake_response(OID_IF_NUMBER, TAG_INTEGER, &[7])), None);
        assert_eq!(extract_integer(&fake_response(OID_IF_NUMBER, TAG_INTEGER, &[0xFF])), None, "négatif");
    }

    #[test]
    fn long_form_lengths() {
        let descr = "x".repeat(300);
        let response = fake_response(OID_SYS_DESCR, TAG_OCTET_STRING, descr.as_bytes());
        assert_eq!(extract_string(&response).as_deref(), Some(descr.as_str()));
    }

    #[test]
    fn agent_error_status_is_reported() {
        let mut varbind = ber_oid(OID_SYS_NAME);
        varbind.extend_from_slice(&[TAG_NULL, 0]);
        let mut pdu = ber_integer(9);
        pdu.extend(ber_integer(2));
        pdu.extend(ber_integer(1));
        pdu.extend(tlv(TAG_SEQUENCE, &tlv(TAG_SEQUENCE, &varbind)));
        let mut message = ber_integer(0);
        message.extend(tlv(TAG_OCTET_STRING, b"public"));
        message.extend(tlv(TAG_GET_RESPONSE, &pdu));
        assert_eq!(parse_get_response(&tlv(TAG_SEQUENCE, &message)), Err(SnmpError::AgentError(2)));
    }

    #[test]
    fn format_uptime_matches_swift() {
        assert_eq!(format_uptime(0), "0 min");
        assert_eq!(format_uptime(5_900), "0 min");
        assert_eq!(format_uptime(6_000), "1 min");
        assert_eq!(format_uptime(366_100), "1 h 1 min");
        assert_eq!(format_uptime(9_000_000), "1 j 1 h");
    }

    #[test]
    fn get_request_encodes_oid_and_community() {
        let request = build_get_request(OID_SYS_NAME, "public", 1);
        let contains = |needle: &[u8]| request.windows(needle.len()).any(|w| w == needle);
        assert!(contains(&[0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x05, 0x00]));
        assert!(contains(b"public"));
        assert_eq!(request[0], TAG_SEQUENCE);
        // Arc ≥ 128 en base 128.
        assert_eq!(base128(300), [0x82, 0x2C]);
        assert_eq!(base128(0), [0]);
        assert_eq!(ber_integer(0x80), [TAG_INTEGER, 2, 0, 0x80]);
    }

    #[test]
    fn malformed_buffers_never_panic() {
        let response = fake_response(OID_SYS_NAME, TAG_OCTET_STRING, b"router");
        for len in 0..response.len() {
            let _ = parse_get_response(&response[..len]);
        }
        for i in 0..response.len() {
            for flip in [0x00, 0xFF, 0x80, 0x84, 0x7F] {
                let mut mutated = response.clone();
                mutated[i] = flip;
                let _ = parse_get_response(&mutated);
            }
        }
        // Longueur annoncée énorme.
        let _ = parse_get_response(&[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02]);
        let _ = parse_get_response(&[0x30, 0x89, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }
}
