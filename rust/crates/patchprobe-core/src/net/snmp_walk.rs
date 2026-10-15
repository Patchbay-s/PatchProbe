//! « Walk » SNMP du groupe système (sysDescr, sysUpTime, sysContact, sysName, sysLocation,
//! ifNumber) — port de `SNMPService.walkSystemInfo`.

use std::net::SocketAddrV4;
use std::time::Duration;

use crate::proto::snmp::{self, SnmpSystemInfo};
use crate::resolve::techniques::snmp_get;

async fn get_string(target: SocketAddrV4, oid: &[u32], community: &str, timeout: Duration) -> Option<String> {
    let response = snmp_get(target, oid, community, timeout).await.ok()?;
    snmp::extract_string(&response).and_then(|s| crate::proto::sanitize_name(&s).map(|_| s.trim().to_owned()))
}

async fn get_integer(target: SocketAddrV4, oid: &[u32], community: &str, timeout: Duration) -> Option<u64> {
    let response = snmp_get(target, oid, community, timeout).await.ok()?;
    snmp::extract_integer(&response)
}

/// Interroge les six scalaires en parallèle ; `None` si l'agent n'a rien répondu.
pub async fn system_info(target: SocketAddrV4, community: &str, timeout: Duration) -> Option<SnmpSystemInfo> {
    let (descr, uptime, contact, name, location, if_number) = tokio::join!(
        get_string(target, snmp::OID_SYS_DESCR, community, timeout),
        get_integer(target, snmp::OID_SYS_UPTIME, community, timeout),
        get_string(target, snmp::OID_SYS_CONTACT, community, timeout),
        get_string(target, snmp::OID_SYS_NAME, community, timeout),
        get_string(target, snmp::OID_SYS_LOCATION, community, timeout),
        get_integer(target, snmp::OID_IF_NUMBER, community, timeout),
    );
    let info = SnmpSystemInfo {
        sys_descr: descr,
        sys_up_time: uptime.map(snmp::format_uptime),
        sys_contact: contact,
        sys_name: name,
        sys_location: location,
        if_number,
    };
    (!info.is_empty()).then_some(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn walks_a_fake_agent() {
        let agent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = agent.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((len, from)) = agent.recv_from(&mut buf).await {
                let request = &buf[..len];
                let has = |oid: &[u32]| {
                    let last = u8::try_from(oid[oid.len() - 2]).unwrap();
                    let group = u8::try_from(oid[oid.len() - 3]).unwrap();
                    request.windows(3).any(|w| w == [group, last, 0])
                };
                let answer = if has(snmp::OID_SYS_NAME) {
                    snmp::tests::fake_response(snmp::OID_SYS_NAME, 0x04, b"core-switch")
                } else if has(snmp::OID_SYS_UPTIME) {
                    snmp::tests::fake_response(snmp::OID_SYS_UPTIME, 0x43, &[0x00, 0x89, 0x54, 0x40])
                } else if has(snmp::OID_IF_NUMBER) {
                    snmp::tests::fake_response(snmp::OID_IF_NUMBER, 0x02, &[24])
                } else {
                    continue; // les autres OID restent sans réponse
                };
                let _ = agent.send_to(&answer, from).await;
            }
        });
        let info = system_info(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), "public", Duration::from_millis(300))
            .await
            .unwrap();
        assert_eq!(info.sys_name.as_deref(), Some("core-switch"));
        assert_eq!(info.sys_up_time.as_deref(), Some("1 j 1 h"));
        assert_eq!(info.if_number, Some(24));
        assert_eq!(info.sys_descr, None);
    }

    #[tokio::test]
    async fn no_agent_means_none() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        assert!(system_info(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port), "public", Duration::from_millis(200))
            .await
            .is_none());
    }
}
