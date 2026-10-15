//! SMB2 Negotiate + SessionSetup(NTLMSSP NEGOTIATE) pour lire le nom de machine dans le
//! CHALLENGE NTLM, sans authentification — port de `SMBNameService.swift`.
#![deny(clippy::indexing_slicing)]

use super::{le16, le32, sanitize_name, Parsed};

/// Taille maximale acceptée pour une trame NBSS (la version Swift : < 1 Mo).
pub const MAX_FRAME_LEN: usize = 1_000_000;

fn smb2_header(command: u16, message_id: u64) -> Vec<u8> {
    let mut h = Vec::with_capacity(64);
    h.extend_from_slice(&[0xFE, b'S', b'M', b'B']);
    h.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    h.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    h.extend_from_slice(&0u32.to_le_bytes()); // Status
    h.extend_from_slice(&command.to_le_bytes());
    h.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    h.extend_from_slice(&0u32.to_le_bytes()); // Flags
    h.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    h.extend_from_slice(&message_id.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // Reserved
    h.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    h.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    h.extend_from_slice(&[0u8; 16]); // Signature
    h
}

/// NEGOTIATE proposant SMB 2.0.2 et 2.1.
pub fn build_negotiate_request() -> Vec<u8> {
    let mut msg = smb2_header(0x0000, 0);
    msg.extend_from_slice(&36u16.to_le_bytes()); // StructureSize
    msg.extend_from_slice(&2u16.to_le_bytes()); // DialectCount
    msg.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    msg.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    msg.extend_from_slice(&[0u8; 16]); // ClientGuid
    msg.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    msg.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    msg.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    msg.extend_from_slice(&0x0202u16.to_le_bytes());
    msg.extend_from_slice(&0x0210u16.to_le_bytes());
    msg
}

/// NTLMSSP NEGOTIATE demandant les AV_PAIRs (dont le nom de machine) dans le CHALLENGE.
pub fn build_ntlm_negotiate() -> Vec<u8> {
    let mut m = Vec::with_capacity(32);
    m.extend_from_slice(b"NTLMSSP\0");
    m.extend_from_slice(&1u32.to_le_bytes());
    m.extend_from_slice(&0xA088_8205u32.to_le_bytes());
    for _ in 0..2 {
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.extend_from_slice(&32u32.to_le_bytes());
    }
    m
}

pub fn build_session_setup_request() -> Vec<u8> {
    let ntlm = build_ntlm_negotiate();
    let mut msg = smb2_header(0x0001, 1);
    msg.extend_from_slice(&25u16.to_le_bytes()); // StructureSize
    msg.push(0); // Flags
    msg.push(1); // SecurityMode
    msg.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    msg.extend_from_slice(&0u32.to_le_bytes()); // Channel
    msg.extend_from_slice(&88u16.to_le_bytes()); // SecurityBufferOffset (64 + 24)
    msg.extend_from_slice(&u16::try_from(ntlm.len()).unwrap_or(0).to_le_bytes());
    msg.extend_from_slice(&0u64.to_le_bytes()); // PreviousSessionId
    msg.extend(ntlm);
    msg
}

/// Préfixe NBSS : 0x00 + longueur sur 3 octets big-endian.
pub fn nbss_frame(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(0) & 0x00FF_FFFF;
    let mut frame = len.to_be_bytes().to_vec();
    if let Some(first) = frame.first_mut() {
        *first = 0;
    }
    frame.extend_from_slice(payload);
    frame
}

/// Longueur annoncée par un en-tête NBSS, si acceptable (> 0 et < [`MAX_FRAME_LEN`]).
pub fn nbss_length(header: [u8; 4]) -> Option<usize> {
    let [kind, a, b, c] = header;
    if kind != 0 {
        return None;
    }
    let len = usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c);
    (len > 0 && len < MAX_FRAME_LEN).then_some(len)
}

/// Extrait le nom de machine d'une réponse SESSION_SETUP (en-tête SMB2 de 64 octets inclus).
pub fn parse_session_setup_response(response: &[u8]) -> Parsed {
    if response.get(0..4) != Some(&[0xFE, b'S', b'M', b'B'][..]) {
        return Parsed::Malformed("réponse qui n'est pas du SMB2");
    }
    let (Some(offset), Some(length)) = (le16(response, 64 + 4), le16(response, 64 + 6)) else {
        return Parsed::Malformed("corps SESSION_SETUP tronqué");
    };
    let (offset, length) = (usize::from(offset), usize::from(length));
    let Some(challenge) = response.get(offset..offset + length).filter(|_| offset > 0) else {
        return Parsed::Malformed("tampon de sécurité hors de la réponse");
    };
    parse_ntlm_challenge(challenge)
}

pub fn parse_ntlm_challenge(message: &[u8]) -> Parsed {
    if message.len() < 48 || message.get(0..8) != Some(&b"NTLMSSP\0"[..]) {
        return Parsed::Malformed("message NTLMSSP invalide");
    }
    if le32(message, 8) != Some(2) {
        return Parsed::Malformed("message NTLMSSP qui n'est pas un CHALLENGE");
    }
    let (Some(len), Some(offset)) = (le16(message, 40), le32(message, 44)) else {
        return Parsed::Malformed("TargetInfo illisible");
    };
    let Ok(offset) = usize::try_from(offset) else {
        return Parsed::Malformed("TargetInfo hors limites");
    };
    match message.get(offset..offset.saturating_add(usize::from(len))) {
        Some(info) if !info.is_empty() => parse_av_pairs(info),
        Some(_) => Parsed::NoName("CHALLENGE sans TargetInfo"),
        None => Parsed::Malformed("TargetInfo hors du message"),
    }
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair)).collect();
    String::from_utf16_lossy(&units)
}

/// AV_PAIR 1 (nom NetBIOS) prioritaire, sinon 3 (nom DNS).
pub fn parse_av_pairs(data: &[u8]) -> Parsed {
    let mut offset = 0;
    let mut netbios = None;
    let mut dns = None;
    while let (Some(id), Some(len)) = (le16(data, offset), le16(data, offset + 2)) {
        offset += 4;
        let Some(value) = data.get(offset..offset + usize::from(len)) else { break };
        match id {
            0x0000 => break, // MsvAvEOL
            0x0001 => netbios = sanitize_name(&utf16le(value)),
            0x0003 => dns = sanitize_name(&utf16le(value)),
            _ => {}
        }
        offset += usize::from(len);
    }
    match netbios.or(dns) {
        Some(name) => Parsed::Name(name),
        None => Parsed::NoName("aucun nom de machine dans les AV_PAIRs NTLM"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn av_pair(id: u16, value: &str) -> Vec<u8> {
        let encoded: Vec<u8> = value.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = id.to_le_bytes().to_vec();
        out.extend_from_slice(&u16::try_from(encoded.len()).unwrap().to_le_bytes());
        out.extend(encoded);
        out
    }

    pub(crate) fn challenge(netbios: Option<&str>, dns: Option<&str>) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend(av_pair(0x0002, "WORKGROUP"));
        if let Some(name) = dns {
            info.extend(av_pair(0x0003, name));
        }
        if let Some(name) = netbios {
            info.extend(av_pair(0x0001, name));
        }
        info.extend_from_slice(&[0, 0, 0, 0]);
        let mut m = b"NTLMSSP\0".to_vec();
        m.extend_from_slice(&2u32.to_le_bytes());
        m.resize(40, 0);
        m.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
        m.extend_from_slice(&u16::try_from(info.len()).unwrap().to_le_bytes());
        m.extend_from_slice(&56u32.to_le_bytes());
        m.resize(56, 0);
        m.extend(info);
        m
    }

    /// Réponse SESSION_SETUP complète (STATUS_MORE_PROCESSING_REQUIRED) autour d'un CHALLENGE.
    pub(crate) fn session_setup_response(challenge: &[u8]) -> Vec<u8> {
        let mut r = smb2_header(0x0001, 1);
        r.extend_from_slice(&9u16.to_le_bytes());
        r.extend_from_slice(&0u16.to_le_bytes());
        r.extend_from_slice(&72u16.to_le_bytes());
        r.extend_from_slice(&u16::try_from(challenge.len()).unwrap().to_le_bytes());
        r.extend_from_slice(challenge);
        r
    }

    #[test]
    fn extracts_netbios_name_first() {
        let resp = session_setup_response(&challenge(Some("test-storage"), Some("storage.example.invalid")));
        assert_eq!(parse_session_setup_response(&resp), Parsed::Name("test-storage".into()));
        let resp = session_setup_response(&challenge(None, Some("storage.example.invalid")));
        assert_eq!(parse_session_setup_response(&resp), Parsed::Name("storage.example.invalid".into()));
        let resp = session_setup_response(&challenge(None, None));
        assert!(matches!(parse_session_setup_response(&resp), Parsed::NoName(_)));
    }

    #[test]
    fn requests_have_expected_layout() {
        let negotiate = build_negotiate_request();
        assert_eq!(negotiate.len(), 64 + 36 + 4);
        let setup = build_session_setup_request();
        assert_eq!(setup.len(), 88 + 32);
        assert_eq!(&setup[88..96], b"NTLMSSP\0");
        let frame = nbss_frame(&setup);
        assert_eq!(&frame[..4], &[0, 0, 0, 120]);
        assert_eq!(nbss_length([0, 0, 0, 120]), Some(120));
        assert_eq!(nbss_length([0, 0x0F, 0xFF, 0xFF]), None);
        assert_eq!(nbss_length([0x85, 0, 0, 1]), None);
    }

    #[test]
    fn malformed_never_panics() {
        let resp = session_setup_response(&challenge(Some("PC"), None));
        for len in 0..resp.len() {
            let _ = parse_session_setup_response(&resp[..len]);
        }
        for i in 0..resp.len() {
            let mut m = resp.clone();
            m[i] ^= 0xFF;
            let _ = parse_session_setup_response(&m);
        }
        assert!(matches!(parse_ntlm_challenge(b"garbage"), Parsed::Malformed(_)));
    }
}
