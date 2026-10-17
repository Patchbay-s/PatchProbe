//! Types de la résolution de nom : chaque technique rend un résultat typé, conservé dans une
//! trace par hôte pour le panneau « Diagnostic du nom ».

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Techniques de résolution, dans l'ordre de priorité de la version Swift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TechniqueId {
    /// Nom mémorisé d'un scan précédent.
    Cache,
    /// Reverse DNS système (`getnameinfo`).
    Ptr,
    /// Requête PTR envoyée directement au DNS de la passerelle.
    GatewayDns,
    /// Requête PTR mDNS unicast vers l'hôte (UDP/5353).
    Mdns,
    /// NetBIOS Name Service (UDP/137).
    Nbns,
    /// SMB2/NTLMSSP pré-authentification (TCP/445).
    Smb,
    /// LLMNR unicast (UDP/5355).
    Llmnr,
    /// SNMP sysName (UDP/161, community `public`).
    Snmp,
    /// Titre HTML du service web.
    WebTitle,
    /// Browse Bonjour en fin de scan.
    Bonjour,
    /// Browse SSDP/UPnP en fin de scan.
    Ssdp,
}

impl TechniqueId {
    /// Ordre de préférence quand plusieurs techniques trouvent un nom.
    pub const PRIORITY: [TechniqueId; 9] = [
        Self::GatewayDns,
        Self::Ptr,
        Self::Mdns,
        Self::Nbns,
        Self::Smb,
        Self::Llmnr,
        Self::Snmp,
        Self::WebTitle,
        Self::Cache,
    ];

    /// Techniques proposées comme source de nom préférée (directes, rejouées à chaque scan).
    pub const PREFERABLE: [TechniqueId; 8] =
        [Self::GatewayDns, Self::Ptr, Self::Mdns, Self::Nbns, Self::Smb, Self::Llmnr, Self::Snmp, Self::WebTitle];

    pub fn label(self) -> &'static str {
        match self {
            Self::Cache => "Cache",
            Self::Ptr => "PTR (DNS système)",
            Self::GatewayDns => "DNS du routeur",
            Self::Mdns => "mDNS",
            Self::Nbns => "NetBIOS (NBNS)",
            Self::Smb => "SMB2/NTLMSSP",
            Self::Llmnr => "LLMNR",
            Self::Snmp => "SNMP sysName",
            Self::WebTitle => "Titre web",
            Self::Bonjour => "Bonjour",
            Self::Ssdp => "SSDP/UPnP",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Ptr => "ptr",
            Self::GatewayDns => "gatewayDns",
            Self::Mdns => "mdns",
            Self::Nbns => "nbns",
            Self::Smb => "smb",
            Self::Llmnr => "llmnr",
            Self::Snmp => "snmp",
            Self::WebTitle => "webTitle",
            Self::Bonjour => "bonjour",
            Self::Ssdp => "ssdp",
        }
    }
}

/// Résultat d'une technique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "camelCase")]
pub enum Outcome {
    /// Un nom a été obtenu.
    Found(String),
    /// Réponse obtenue (ou refus explicite) mais sans nom, avec la raison (NXDOMAIN, port
    /// fermé, aucun AV_PAIR…).
    NotFound(String),
    /// Aucune réponse avant le délai.
    Timeout,
    /// Échec explicite (connexion refusée, paquet malformé, erreur réseau…).
    Error(String),
    /// Technique non tentée, avec la raison (pas de passerelle, aucun port web…).
    Skipped(String),
}

impl Outcome {
    pub fn found(&self) -> Option<&str> {
        match self {
            Self::Found(name) => Some(name),
            _ => None,
        }
    }

    pub fn error(message: impl std::fmt::Display) -> Self {
        Self::Error(message.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TechniqueResult {
    pub technique: TechniqueId,
    pub outcome: Outcome,
    pub duration_ms: u64,
}

impl TechniqueResult {
    pub fn new(technique: TechniqueId, outcome: Outcome, duration: Duration) -> Self {
        let duration_ms = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        Self { technique, outcome, duration_ms }
    }
}

/// Trace complète de la résolution d'un hôte.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NameTrace {
    pub ip: Ipv4Addr,
    pub results: Vec<TechniqueResult>,
    /// Nom retenu et technique source.
    pub chosen: Option<ChosenName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChosenName {
    pub name: String,
    pub technique: TechniqueId,
}

impl NameTrace {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self { ip, results: Vec::new(), chosen: None }
    }

    pub fn push(&mut self, result: TechniqueResult) {
        self.results.push(result);
    }

    pub fn result(&self, technique: TechniqueId) -> Option<&TechniqueResult> {
        self.results.iter().rev().find(|r| r.technique == technique)
    }

    /// Choisit le nom parmi les résultats `Found` : la technique préférée d'abord si elle a
    /// trouvé un nom, sinon selon [`TechniqueId::PRIORITY`].
    pub fn choose(&mut self, preferred: Option<TechniqueId>) {
        self.chosen = preferred.into_iter().chain(TechniqueId::PRIORITY).find_map(|technique| {
            self.result(technique)
                .and_then(|r| r.outcome.found())
                .map(|name| ChosenName { name: name.to_owned(), technique })
        });
    }

    /// Fixe le nom (découverte de fin de scan) en ajoutant le résultat à la trace.
    pub fn set_discovered(&mut self, technique: TechniqueId, name: String) {
        self.push(TechniqueResult { technique, outcome: Outcome::Found(name.clone()), duration_ms: 0 });
        self.chosen = Some(ChosenName { name, technique });
    }
}

/// Mode de résolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveMode {
    /// Pendant un scan : cache utilisé, titre web seulement si aucun autre nom.
    Scan,
    /// Diagnostic : toutes les techniques, cache ignoré.
    Diagnostic,
}

/// Abstraction utilisée par le moteur de scan (implémentée par `resolve::Resolver`).
#[async_trait]
pub trait NameResolution: Send + Sync + 'static {
    /// Résout le nom d'un hôte vivant.
    async fn resolve(&self, ip: Ipv4Addr, open_ports: &[u16], mode: ResolveMode) -> NameTrace;

    /// Découverte active de fin de scan (Bonjour, SSDP) : noms par IP avec la technique source.
    async fn discover(&self) -> HashMap<Ipv4Addr, (String, TechniqueId)>;
}

/// Résolution désactivée (tests, ou utilisateur qui ne veut pas de noms).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoNameResolution;

#[async_trait]
impl NameResolution for NoNameResolution {
    async fn resolve(&self, ip: Ipv4Addr, _open_ports: &[u16], _mode: ResolveMode) -> NameTrace {
        NameTrace::new(ip)
    }

    async fn discover(&self) -> HashMap<Ipv4Addr, (String, TechniqueId)> {
        HashMap::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choose_follows_priority() {
        let mut trace = NameTrace::new(Ipv4Addr::LOCALHOST);
        trace.push(TechniqueResult::new(TechniqueId::Nbns, Outcome::Found("PC".into()), Duration::ZERO));
        trace.push(TechniqueResult::new(TechniqueId::Ptr, Outcome::Timeout, Duration::ZERO));
        trace.push(TechniqueResult::new(
            TechniqueId::GatewayDns,
            Outcome::Found("pc.example.invalid".into()),
            Duration::ZERO,
        ));
        trace.choose(None);
        let chosen = trace.chosen.unwrap();
        assert_eq!(chosen.name, "pc.example.invalid");
        assert_eq!(chosen.technique, TechniqueId::GatewayDns);
    }

    #[test]
    fn preferred_technique_wins_then_priority_applies() {
        let found =
            |technique, name: &str| TechniqueResult::new(technique, Outcome::Found(name.into()), Duration::ZERO);
        let mut trace = NameTrace::new(Ipv4Addr::LOCALHOST);
        trace.push(found(TechniqueId::GatewayDns, "pc.example.invalid"));
        trace.push(found(TechniqueId::WebTitle, "Panel"));
        trace.choose(Some(TechniqueId::WebTitle));
        assert_eq!(trace.chosen.as_ref().map(|c| c.technique), Some(TechniqueId::WebTitle));
        trace.choose(Some(TechniqueId::Snmp));
        assert_eq!(trace.chosen.as_ref().map(|c| c.technique), Some(TechniqueId::GatewayDns));
        trace.choose(None);
        assert_eq!(trace.chosen.as_ref().map(|c| c.technique), Some(TechniqueId::GatewayDns));
    }

    #[test]
    fn outcome_serialization_is_tagged() {
        let json = serde_json::to_value(Outcome::Found("x".into())).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "found", "detail": "x"}));
        let json = serde_json::to_value(Outcome::Timeout).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "timeout"}));
    }
}
