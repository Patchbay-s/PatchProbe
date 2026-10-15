//! Wake-on-LAN : paquet magique UDP (6 × 0xFF puis 16 × la MAC) — port de
//! `WakeOnLanService.swift`.

use std::net::{Ipv4Addr, SocketAddrV4};

use thiserror::Error;
use tokio::net::UdpSocket;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum WolError {
    #[error("Adresse MAC invalide : « {0} ».")]
    InvalidMac(String),
    #[error("Envoi du paquet magique impossible : {0}")]
    Send(String),
}

/// MAC en 6 octets : séparateurs `:` ou `-` (1 ou 2 chiffres hex par octet) ou 12 chiffres hex.
pub fn parse_mac(mac: &str) -> Result<[u8; 6], WolError> {
    let normalized = crate::oui::normalize_mac(mac).ok_or_else(|| WolError::InvalidMac(mac.to_owned()))?;
    let bytes: Vec<u8> = normalized.split(':').filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
    bytes.try_into().map_err(|_| WolError::InvalidMac(mac.to_owned()))
}

pub fn magic_packet(mac: [u8; 6]) -> Vec<u8> {
    let mut packet = vec![0xFF; 6];
    for _ in 0..16 {
        packet.extend_from_slice(&mac);
    }
    packet
}

/// Envoie le paquet magique à `target` (par défaut 255.255.255.255:9). La MAC est validée
/// avant toute opération réseau.
pub async fn send(mac: &str, target: Option<SocketAddrV4>) -> Result<(), WolError> {
    let packet = magic_packet(parse_mac(mac)?);
    let target = target.unwrap_or(SocketAddrV4::new(Ipv4Addr::BROADCAST, 9));
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .await
        .map_err(|e| WolError::Send(e.to_string()))?;
    socket.set_broadcast(true).map_err(|e| WolError::Send(e.to_string()))?;
    let sent = socket.send_to(&packet, target).await.map_err(|e| WolError::Send(e.to_string()))?;
    if sent == packet.len() {
        Ok(())
    } else {
        Err(WolError::Send("paquet partiellement envoyé".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_malformed_mac_without_network() {
        for bad in ["not-a-mac", "AA:BB:CC:DD:EE", "AA:BB:CC:DD:EE:GG", ""] {
            assert!(matches!(send(bad, None).await, Err(WolError::InvalidMac(_))), "{bad}");
        }
    }

    #[test]
    fn accepts_both_separators() {
        assert_eq!(parse_mac("02:00:00:00:00:01"), parse_mac("02-00-00-00-00-01"));
        assert_eq!(parse_mac("020000000001").unwrap(), [0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn packet_layout() {
        let packet = magic_packet([1, 2, 3, 4, 5, 6]);
        assert_eq!(packet.len(), 102);
        assert_eq!(&packet[..6], &[0xFF; 6]);
        assert_eq!(&packet[96..], &[1, 2, 3, 4, 5, 6]);
    }

    #[tokio::test]
    async fn sends_to_loopback_listener() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(addr) = listener.local_addr().unwrap() else { unreachable!() };
        send("02:00:00:00:00:01", Some(addr)).await.unwrap();
        let mut buf = [0u8; 200];
        let len = listener.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], magic_packet([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]).as_slice());
    }
}
