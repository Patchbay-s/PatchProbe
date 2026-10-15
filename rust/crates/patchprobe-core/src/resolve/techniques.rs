//! Les techniques de résolution, chacune indépendante et rendant un [`Outcome`] typé.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use super::types::{Outcome, TechniqueId, TechniqueResult};
use crate::proto::{dns, http_title, nbns, smb, snmp, Parsed};

/// Exécute une technique et chronomètre son résultat.
pub async fn timed<F>(technique: TechniqueId, future: F) -> TechniqueResult
where
    F: std::future::Future<Output = Outcome>,
{
    let started = Instant::now();
    let outcome = future.await;
    TechniqueResult::new(technique, outcome, started.elapsed())
}

pub fn parsed_to_outcome(parsed: Parsed) -> Outcome {
    match parsed {
        Parsed::Name(name) => Outcome::Found(name),
        Parsed::NoName(why) => Outcome::NotFound(why.to_owned()),
        Parsed::Malformed(why) => Outcome::Error(format!("réponse malformée : {why}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpError {
    Timeout,
    /// ICMP « port injoignable » remonté par l'OS (ECONNREFUSED, ou WSAECONNRESET sous Windows).
    PortClosed,
    Io(String),
}

pub fn is_port_unreachable(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset)
}

/// Envoie `payload` à `target` depuis un socket connecté (seules les réponses de `target` sont
/// lues) et attend une réponse acceptée par `accept` avant `timeout`.
pub async fn udp_request(
    target: SocketAddrV4,
    payload: &[u8],
    timeout: Duration,
    accept: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, UdpError> {
    let socket =
        UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await.map_err(|e| UdpError::Io(e.to_string()))?;
    socket.connect(target).await.map_err(|e| UdpError::Io(e.to_string()))?;
    let deadline = tokio::time::Instant::now() + timeout;
    match socket.send(payload).await {
        Ok(_) => {}
        Err(e) if is_port_unreachable(&e) => return Err(UdpError::PortClosed),
        Err(e) => return Err(UdpError::Io(e.to_string())),
    }
    let mut buffer = vec![0u8; 4096];
    loop {
        match tokio::time::timeout_at(deadline, socket.recv(&mut buffer)).await {
            Err(_) => return Err(UdpError::Timeout),
            Ok(Ok(len)) => {
                let data = buffer.get(..len).unwrap_or_default();
                if accept(data) {
                    return Ok(data.to_vec());
                }
            }
            Ok(Err(e)) if is_port_unreachable(&e) => return Err(UdpError::PortClosed),
            Ok(Err(e)) => return Err(UdpError::Io(e.to_string())),
        }
    }
}

fn udp_error_outcome(error: UdpError, protocol: &str, port: u16) -> Outcome {
    match error {
        UdpError::Timeout => Outcome::Timeout,
        UdpError::PortClosed => {
            Outcome::NotFound(format!("{protocol} : port UDP {port} fermé (ICMP port injoignable)"))
        }
        UdpError::Io(message) => Outcome::Error(message),
    }
}

/// PTR inverse via le résolveur système (`getnameinfo`), borné par `timeout`.
pub async fn system_ptr(ip: Ipv4Addr, timeout: Duration) -> Outcome {
    let lookup = tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&IpAddr::V4(ip)));
    match tokio::time::timeout(timeout, lookup).await {
        Err(_) => Outcome::Timeout,
        Ok(Err(join_error)) => Outcome::error(join_error),
        Ok(Ok(Err(error))) => Outcome::NotFound(format!("le résolveur système ne connaît pas cette adresse ({error})")),
        Ok(Ok(Ok(name))) => match crate::proto::sanitize_name(&name) {
            Some(name) if name.parse::<Ipv4Addr>().is_err() => Outcome::Found(name),
            _ => Outcome::NotFound("le résolveur système n'a renvoyé que l'adresse".into()),
        },
    }
}

/// Requête PTR envoyée à un serveur DNS précis (passerelle:53, hôte:5353 pour mDNS, hôte:5355
/// pour LLMNR).
pub async fn dns_ptr(
    server: SocketAddrV4,
    ip: Ipv4Addr,
    timeout: Duration,
    recursion: bool,
    protocol: &str,
) -> Outcome {
    let id: u16 = rand::random();
    let query = dns::build_ptr_query(ip, id, recursion);
    let accept = move |data: &[u8]| crate::proto::be16(data, 0) == Some(id);
    match udp_request(server, &query, timeout, accept).await {
        Ok(response) => parsed_to_outcome(dns::parse_ptr_response(&response, Some(id))),
        Err(error) => udp_error_outcome(error, protocol, server.port()),
    }
}

pub async fn gateway_dns(ip: Ipv4Addr, gateway: Option<Ipv4Addr>, port: u16, timeout: Duration) -> Outcome {
    match gateway {
        None => Outcome::Skipped("passerelle par défaut non détectée".into()),
        Some(gw) if gw == ip => Outcome::Skipped("l'hôte est la passerelle elle-même".into()),
        Some(gw) => dns_ptr(SocketAddrV4::new(gw, port), ip, timeout, true, "DNS du routeur").await,
    }
}

pub async fn nbns_query(target: SocketAddrV4, timeout: Duration) -> Outcome {
    let id: u16 = rand::random();
    let query = nbns::build_nbstat_query(id);
    let accept = move |data: &[u8]| crate::proto::be16(data, 0) == Some(id);
    match udp_request(target, &query, timeout, accept).await {
        Ok(response) => parsed_to_outcome(nbns::parse_nbstat_response(&response)),
        Err(error) => udp_error_outcome(error, "NBNS", target.port()),
    }
}

pub async fn snmp_get(
    target: SocketAddrV4,
    oid: &[u32],
    community: &str,
    timeout: Duration,
) -> Result<Vec<u8>, UdpError> {
    let request_id = rand::random::<u32>() & 0x7FFF_FFFF;
    let request = snmp::build_get_request(oid, community, request_id);
    udp_request(target, &request, timeout, |_| true).await
}

pub async fn snmp_sys_name(target: SocketAddrV4, community: &str, timeout: Duration) -> Outcome {
    match snmp_get(target, snmp::OID_SYS_NAME, community, timeout).await {
        Err(error) => udp_error_outcome(error, "SNMP", target.port()),
        Ok(response) => match snmp::parse_get_response(&response) {
            Ok((_, snmp::SnmpValue::OctetString(bytes))) => {
                match crate::proto::sanitize_name(&String::from_utf8_lossy(&bytes)) {
                    Some(name) => Outcome::Found(name),
                    None => Outcome::NotFound("sysName vide".into()),
                }
            }
            Ok((_, other)) => Outcome::NotFound(format!("sysName de type inattendu ({other:?})")),
            Err(snmp::SnmpError::AgentError(code)) => Outcome::NotFound(snmp::SnmpError::AgentError(code).to_string()),
            Err(error) => Outcome::Error(error.to_string()),
        },
    }
}

async fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    let len =
        smb::nbss_length(header).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "trame NBSS invalide"))?;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn smb_exchange(target: SocketAddrV4) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(target).await?;
    stream.write_all(&smb::nbss_frame(&smb::build_negotiate_request())).await?;
    read_frame(&mut stream).await?;
    stream.write_all(&smb::nbss_frame(&smb::build_session_setup_request())).await?;
    read_frame(&mut stream).await
}

/// SMB2 + NTLMSSP pré-authentification (TCP/445), toute l'exception bornée par `timeout`.
pub async fn smb_name(target: SocketAddrV4, timeout: Duration) -> Outcome {
    match tokio::time::timeout(timeout, smb_exchange(target)).await {
        Err(_) => Outcome::Timeout,
        Ok(Ok(response)) => parsed_to_outcome(smb::parse_session_setup_response(&response)),
        Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            Outcome::NotFound(format!("port TCP {} fermé (pas de partage SMB)", target.port()))
        }
        Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => {
            Outcome::Error("connexion SMB fermée par l'hôte avant la réponse".into())
        }
        Ok(Err(e)) => Outcome::error(e),
    }
}

/// Client HTTP pour les titres web et les descripteurs SSDP : certificats auto-signés acceptés
/// (services LAN), aucun proxy (le scan doit rester sur le réseau local).
pub fn http_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::limited(3))
        .user_agent("PatchProbe")
        .build()
        .ok()
}

/// Lit au plus `limit` octets du corps.
pub async fn read_limited(mut response: reqwest::Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < limit {
        match response.chunk().await {
            Ok(Some(chunk)) => body.extend_from_slice(&chunk),
            _ => break,
        }
    }
    body.truncate(limit);
    body
}

enum TitleAttempt {
    Title(String),
    NoTitle(String),
    Timeout,
    Failed(String),
}

async fn fetch_title(client: &reqwest::Client, ip: Ipv4Addr, port: u16, timeout: Duration) -> TitleAttempt {
    let url = format!("{}://{ip}:{port}/", http_title::scheme_for_title_port(port));
    match client.get(&url).timeout(timeout).send().await {
        Err(e) if e.is_timeout() => TitleAttempt::Timeout,
        Err(e) => TitleAttempt::Failed(format!("port {port} : {e}")),
        Ok(response) if response.status().as_u16() >= 500 => {
            TitleAttempt::NoTitle(format!("port {port} : HTTP {}", response.status().as_u16()))
        }
        Ok(response) => {
            let status = response.status().as_u16();
            let body = match tokio::time::timeout(timeout, read_limited(response, 8192)).await {
                Ok(body) => body,
                Err(_) => return TitleAttempt::Timeout,
            };
            match http_title::extract_title(&http_title::decode_body(&body)) {
                Some(title) => TitleAttempt::Title(title),
                None => TitleAttempt::NoTitle(format!("port {port} : HTTP {status} sans <title>")),
            }
        }
    }
}

/// Titre HTML du premier service web qui en expose un (au plus 4 ports essayés).
pub async fn web_title(
    client: Option<&reqwest::Client>,
    ip: Ipv4Addr,
    open_ports: &[u16],
    timeout: Duration,
) -> Outcome {
    if open_ports.is_empty() {
        return Outcome::Skipped("aucun port TCP ouvert".into());
    }
    let Some(client) = client else {
        return Outcome::Error("client HTTP indisponible".into());
    };
    let mut notes = Vec::new();
    let mut timeouts = 0;
    let ports = http_title::ordered_ports(open_ports, 4);
    for port in &ports {
        match fetch_title(client, ip, *port, timeout).await {
            TitleAttempt::Title(title) => return Outcome::Found(title),
            TitleAttempt::NoTitle(note) | TitleAttempt::Failed(note) => notes.push(note),
            TitleAttempt::Timeout => timeouts += 1,
        }
    }
    if timeouts == ports.len() {
        Outcome::Timeout
    } else {
        Outcome::NotFound(notes.join(" ; "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn udp_server(reply: impl Fn(&[u8]) -> Option<Vec<u8>> + Send + 'static) -> SocketAddrV4 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(addr) = socket.local_addr().unwrap() else { unreachable!() };
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((len, from)) = socket.recv_from(&mut buf).await {
                if let Some(answer) = reply(&buf[..len]) {
                    let _ = socket.send_to(&answer, from).await;
                }
            }
        });
        addr
    }

    fn ptr_answer(query: &[u8], name: &str) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] = 0x84;
        r[3] = 0x00;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 0x0C, 0, 12, 0, 1, 0, 0, 0, 60]);
        let mut rdata = Vec::new();
        for label in name.split('.') {
            rdata.push(u8::try_from(label.len()).unwrap());
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        r.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        r.extend(rdata);
        r
    }

    #[tokio::test]
    async fn dns_ptr_over_loopback() {
        let server = udp_server(|q| Some(ptr_answer(q, "storage.example.invalid"))).await;
        let outcome = dns_ptr(server, Ipv4Addr::new(192, 0, 2, 5), Duration::from_secs(1), true, "DNS").await;
        assert_eq!(outcome, Outcome::Found("storage.example.invalid".into()));
    }

    #[tokio::test]
    async fn ignores_mismatched_transaction_ids_then_times_out() {
        let server = udp_server(|q| {
            let mut answer = ptr_answer(q, "spoof.example.invalid");
            answer[0] ^= 0xFF;
            Some(answer)
        })
        .await;
        let outcome = dns_ptr(server, Ipv4Addr::LOCALHOST, Duration::from_millis(200), false, "LLMNR").await;
        assert_eq!(outcome, Outcome::Timeout);
    }

    #[tokio::test]
    async fn silent_server_times_out_and_closed_port_is_reported() {
        let silent = udp_server(|_| None).await;
        assert_eq!(nbns_query(silent, Duration::from_millis(100)).await, Outcome::Timeout);
        // Port fermé : le noyau renvoie ICMP « port injoignable » sur loopback.
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(closed) = socket.local_addr().unwrap() else { unreachable!() };
        drop(socket);
        let outcome = nbns_query(closed, Duration::from_millis(300)).await;
        assert!(matches!(outcome, Outcome::NotFound(ref why) if why.contains("fermé")), "{outcome:?}");
    }

    #[tokio::test]
    async fn nbns_over_loopback() {
        let server = udp_server(|q| {
            let mut r = q.to_vec();
            r[2] = 0x84;
            r.extend_from_slice(&[0xC0, 0x0C, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41, 1]);
            r.extend(b"MEDIA-PC       ");
            r.push(0x00);
            r.extend_from_slice(&[0x04, 0x00]);
            Some(r)
        })
        .await;
        assert_eq!(nbns_query(server, Duration::from_secs(1)).await, Outcome::Found("MEDIA-PC".into()));
    }

    #[tokio::test]
    async fn snmp_over_loopback() {
        let server = udp_server(|_| Some(snmp::tests::fake_response(snmp::OID_SYS_NAME, 0x04, b"switch-garage"))).await;
        assert_eq!(
            snmp_sys_name(server, "public", Duration::from_secs(1)).await,
            Outcome::Found("switch-garage".into())
        );
        let garbage = udp_server(|_| Some(vec![0x30, 0x84, 0xFF])).await;
        assert!(matches!(snmp_sys_name(garbage, "public", Duration::from_secs(1)).await, Outcome::Error(_)));
    }

    #[tokio::test]
    async fn smb_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(addr) = listener.local_addr().unwrap() else { unreachable!() };
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_frame(&mut stream).await.unwrap();
            stream.write_all(&smb::nbss_frame(&[0xFE, b'S', b'M', b'B', 0, 0])).await.unwrap();
            read_frame(&mut stream).await.unwrap();
            let challenge = smb::tests::challenge(Some("TEST-SERVER"), Some("files.example.invalid"));
            let response = smb::tests::session_setup_response(&challenge);
            stream.write_all(&smb::nbss_frame(&response)).await.unwrap();
        });
        assert_eq!(smb_name(addr, Duration::from_secs(1)).await, Outcome::Found("TEST-SERVER".into()));
    }

    #[tokio::test]
    async fn smb_closed_port_and_hanging_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(addr) = listener.local_addr().unwrap() else { unreachable!() };
        let hang = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        assert_eq!(smb_name(addr, Duration::from_millis(150)).await, Outcome::Timeout);
        hang.abort();
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let std::net::SocketAddr::V4(closed_addr) = closed.local_addr().unwrap() else { unreachable!() };
        drop(closed);
        assert!(matches!(smb_name(closed_addr, Duration::from_secs(5)).await, Outcome::NotFound(_)));
    }

    #[tokio::test]
    async fn web_title_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = "<html><head><title>Home Assistant</title></head></html>";
                let reply =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        let client = http_client();
        let outcome = web_title(client.as_ref(), Ipv4Addr::LOCALHOST, &[port], Duration::from_secs(2)).await;
        assert_eq!(outcome, Outcome::Found("Home Assistant".into()));
        let none = web_title(client.as_ref(), Ipv4Addr::LOCALHOST, &[], Duration::from_secs(1)).await;
        assert!(matches!(none, Outcome::Skipped(_)));
    }

    #[tokio::test]
    async fn gateway_dns_skips_without_gateway() {
        assert!(matches!(
            gateway_dns(Ipv4Addr::LOCALHOST, None, 53, Duration::from_millis(10)).await,
            Outcome::Skipped(_)
        ));
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        assert!(matches!(gateway_dns(ip, Some(ip), 53, Duration::from_millis(10)).await, Outcome::Skipped(_)));
    }

    #[tokio::test]
    async fn system_ptr_for_localhost_does_not_hang() {
        let outcome = system_ptr(Ipv4Addr::LOCALHOST, Duration::from_secs(3)).await;
        assert!(!matches!(outcome, Outcome::Skipped(_)));
    }
}
