use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;

use super::*;

/// Port UDP libre (lié puis relâché) : toute requête y obtiendra « port injoignable ».
fn closed_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn closed_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Faux répondeur NBNS sur loopback.
async fn fake_nbns() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((len, from)) = socket.recv_from(&mut buf).await {
            let mut r = buf[..len].to_vec();
            r[2] = 0x84;
            r.extend_from_slice(&[0xC0, 0x0C, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 0x41, 1]);
            r.extend(b"MEDIA-PC       ");
            r.extend_from_slice(&[0x00, 0x04, 0x00]);
            let _ = socket.send_to(&r, from).await;
        }
    });
    port
}

/// Faux service web sur loopback : renvoie une page dont le titre est « Test Panel ».
async fn fake_http() -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf).await;
                let body = "<html><head><title>Test Panel</title></head></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    port
}

fn config(nbns: u16) -> ResolverConfig {
    ResolverConfig {
        name_timeout: Duration::from_millis(400),
        web_title_timeout: Duration::from_millis(300),
        discovery_budget: Duration::from_millis(100),
        gateway: None,
        snmp_community: "public".into(),
        preferred_name: None,
        ports: TechniquePorts {
            dns: closed_udp_port(),
            mdns: closed_udp_port(),
            nbns,
            llmnr: closed_udp_port(),
            snmp: closed_udp_port(),
            smb: closed_tcp_port(),
        },
    }
}

fn fixed_clock() -> i64 {
    1_000_000
}

fn outcome(trace: &NameTrace, technique: TechniqueId) -> Outcome {
    trace.result(technique).map(|r| r.outcome.clone()).unwrap()
}

#[tokio::test]
async fn full_trace_records_every_technique() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let resolver = Resolver::new(config(fake_nbns().await), cache.clone()).with_clock(fixed_clock);
    let trace = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Scan).await;

    let techniques: Vec<TechniqueId> = trace.results.iter().map(|r| r.technique).collect();
    assert_eq!(
        techniques,
        [
            TechniqueId::Ptr,
            TechniqueId::GatewayDns,
            TechniqueId::Mdns,
            TechniqueId::Nbns,
            TechniqueId::Smb,
            TechniqueId::Llmnr,
            TechniqueId::Snmp,
            TechniqueId::WebTitle,
        ]
    );
    assert_eq!(outcome(&trace, TechniqueId::Nbns), Outcome::Found("MEDIA-PC".into()));
    assert!(matches!(outcome(&trace, TechniqueId::GatewayDns), Outcome::Skipped(_)));
    // SMB : sous Windows, un port TCP fermé n'est refusé qu'après ~2 s (> timeout du test).
    let smb = outcome(&trace, TechniqueId::Smb);
    assert!(matches!(smb, Outcome::NotFound(_) | Outcome::Timeout), "{smb:?}");
    for closed in [TechniqueId::Mdns, TechniqueId::Llmnr, TechniqueId::Snmp] {
        assert!(matches!(outcome(&trace, closed), Outcome::NotFound(ref why) if why.contains("fermé")), "{closed:?}");
    }
    assert!(trace.chosen.is_some());
    assert!(matches!(cache.lock().unwrap().lookup(Ipv4Addr::LOCALHOST, fixed_clock()), CacheLookup::Hit { .. }));

    // Second passage en mode scan : la chaîne lente est sautée grâce au cache.
    let again = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Scan).await;
    assert!(matches!(outcome(&again, TechniqueId::Nbns), Outcome::Skipped(ref why) if why.contains("cache")));
    assert!(again.chosen.is_some());

    // Diagnostic : tout est rejoué, cache ignoré.
    let diag = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Diagnostic).await;
    assert_eq!(outcome(&diag, TechniqueId::Nbns), Outcome::Found("MEDIA-PC".into()));
    assert!(diag.result(TechniqueId::Cache).is_none());
}

#[tokio::test]
async fn failures_are_cached_briefly() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let resolver = Resolver::new(config(closed_udp_port()), cache.clone()).with_clock(fixed_clock);
    let ip = Ipv4Addr::LOCALHOST;
    cache.lock().unwrap().clear();
    let trace = resolver.resolve(ip, &[], ResolveMode::Scan).await;
    if let Some(chosen) = &trace.chosen {
        // Le résolveur système connaît « localhost » : le PTR suffit, rien à mettre en échec.
        assert_eq!(chosen.technique, TechniqueId::Ptr);
    } else {
        assert_eq!(cache.lock().unwrap().lookup(ip, fixed_clock()), CacheLookup::RecentFailure);
        let again = resolver.resolve(ip, &[], ResolveMode::Scan).await;
        assert!(matches!(outcome(&again, TechniqueId::Nbns), Outcome::Skipped(ref why) if why.contains("échec")));
    }
}

#[tokio::test]
async fn discovery_fills_cache() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let resolver = Resolver::new(config(closed_udp_port()), cache.clone()).with_clock(fixed_clock);
    resolver.remember_discovered(Ipv4Addr::new(198, 51, 100, 9), "media-device-1", TechniqueId::Ssdp);
    assert_eq!(
        cache.lock().unwrap().lookup(Ipv4Addr::new(198, 51, 100, 9), fixed_clock()),
        CacheLookup::Hit { name: "media-device-1".into(), technique: Some(TechniqueId::Ssdp) }
    );
    let _ = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
}

#[tokio::test]
async fn preferred_web_title_wins_over_other_names() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let config = ResolverConfig { preferred_name: Some(TechniqueId::WebTitle), ..config(fake_nbns().await) };
    let resolver = Resolver::new(config, cache).with_clock(fixed_clock);
    let ports = [fake_http().await];

    let trace = resolver.resolve(Ipv4Addr::LOCALHOST, &ports, ResolveMode::Scan).await;
    assert_eq!(outcome(&trace, TechniqueId::Nbns), Outcome::Found("MEDIA-PC".into()));
    assert_eq!(trace.chosen, Some(ChosenName { name: "Test Panel".into(), technique: TechniqueId::WebTitle }));

    // Rescan : le nom est en cache, mais la source préférée est quand même rejouée.
    let again = resolver.resolve(Ipv4Addr::LOCALHOST, &ports, ResolveMode::Scan).await;
    assert_eq!(again.chosen.map(|c| c.technique), Some(TechniqueId::WebTitle));
}

#[tokio::test]
async fn preferred_source_is_not_skipped_by_cache() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let config = ResolverConfig { preferred_name: Some(TechniqueId::Nbns), ..config(fake_nbns().await) };
    let resolver = Resolver::new(config, cache).with_clock(fixed_clock);
    let first = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Scan).await;
    assert_eq!(first.chosen.map(|c| c.technique), Some(TechniqueId::Nbns));
    let again = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Scan).await;
    assert_eq!(outcome(&again, TechniqueId::Nbns), Outcome::Found("MEDIA-PC".into()));
    assert!(matches!(outcome(&again, TechniqueId::Mdns), Outcome::Skipped(ref why) if why.contains("cache")));
    assert_eq!(again.chosen.map(|c| c.technique), Some(TechniqueId::Nbns));
}

#[tokio::test]
async fn preferred_source_without_name_falls_back_to_priority() {
    let cache: SharedCache = Arc::new(Mutex::new(ResolutionCache::default()));
    let config = ResolverConfig { preferred_name: Some(TechniqueId::WebTitle), ..config(fake_nbns().await) };
    let resolver = Resolver::new(config, cache).with_clock(fixed_clock);
    // Aucun port web : le titre web n'a rien, un autre nom est retenu.
    let trace = resolver.resolve(Ipv4Addr::LOCALHOST, &[], ResolveMode::Scan).await;
    assert!(trace.chosen.is_some_and(|c| c.technique != TechniqueId::WebTitle));
}
