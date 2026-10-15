# PatchProbe — portage Rust + Tauri 2

Le code Swift de l'application macOS historique (anciennement IPScanner) n'est pas dans ce
dépôt : il est conservé dans le dépôt historique privé comme référence comportementale et n'est
plus développé. L'application active est dans `rust/` :

```
rust/
├── Cargo.toml                 # workspace
├── crates/
│   ├── patchprobe-core/        # logique pure : modèles, parseurs, protocoles, moteur générique
│   └── patchprobe-platform/    # tout ce qui dépend de l'OS (ping, arp, interface, navigateur…)
└── app/                       # Tauri 2 (src-tauri = crate patchprobe-app) + frontend React/TS/Vite
```

Règle de découpage : `patchprobe-core` ne lance aucun processus et ne lit aucune sortie système ;
il contient en revanche les **parseurs** de sorties texte (ping/arp/traceroute/nmap) pour qu'ils
soient testables avec des fixtures sans OS particulier. Les sockets réseau (TCP/UDP) passent par
tokio, qui est portable : le moteur de scan et les sondes de nom vivent donc dans `core`
(module `net`), sans `cfg(target_os)`. `patchprobe-platform` ne contient que ce qui diffère
réellement d'un OS à l'autre.

## 1. Correspondance fichier Swift → module Rust

### Models
| Swift | Rust |
|---|---|
| `Models/Host.swift` | `core::model::host` (`Host`, `HostStatus`, clés de tri, `subnet_key`, `status_label`) |
| `Models/HostGrouping.swift` | `core::model::grouping` |
| `Models/ScanRange.swift` | `core::range` (`ScanRange`, `ipv4_to_u32`, `prefix_from_mask`) |
| `Models/ScanSettings.swift` | `core::settings` (`ScanSettings`, `TimingPreset::{Rapide, Approfondi}`) |
| `Models/PortPreset.swift` | `core::ports` (`PortPresetKind`, `DEFAULT_TCP_PORTS`, `parse_ports`) |
| `Models/DeviceType.swift` | `core::model::device_type` |
| `Models/ScanSnapshot.swift` | `core::model::snapshot` |
| `Models/ScanDiff.swift` | `core::diff::scan_diff` |
| `Models/SiteProfile.swift` + `SiteProfileDiff.swift` | `core::model::site_profile`, `core::diff::site_profile_diff` |
| `Models/NmapPortResult.swift` (+ parseur XML) | `core::parsers::nmap` (quick-xml) |
| `Models/SNMPSystemInfo.swift` | `core::proto::snmp` |
| `Models/TracerouteHop.swift` | `core::parsers::traceroute` |
| `Models/UDPPortResult.swift` | `core::net::udp_scan` |
| `Models/NetworkProfile.swift` | `platform::netconfig` (signatures seulement, « non supporté ») |

### Services
| Swift | Rust |
|---|---|
| `PortScanner.swift` | `core::net::tcp` + `core::engine` (sémaphore global) |
| `PingService.swift` (exécution) | `platform::ping` (binaire système, flags par OS) |
| `PingService.swift` (parsing, TTL→OS) | `core::parsers::ping` |
| `ArpService.swift` | `platform::arp` (exécution) + `core::parsers::arp` (macOS/Linux/Windows/`/proc/net/arp`) |
| `NetworkInterface.swift` | `platform::iface` (crate `if-addrs`) + `core::range::InterfaceInfo` (cidr, scan_range_text) |
| `OUIVendorDatabase.swift` + `Resources/OUIVendors.json` | `core::oui` (JSON embarqué via `include_str!`, chargé paresseusement) |
| `ResolutionCache.swift` | `core::resolve::cache` (TTL, taille bornée, échecs courts) |
| `GatewayDNSResolver.swift` | `core::resolve::techniques::gateway_dns` + `platform::gateway` (détection passerelle) |
| `CFHostResolver.swift` | `core::resolve::techniques::mdns` (requête PTR unicast vers 224.0.0.251:5353 / l'hôte:5353) |
| `NBNSService.swift` | `core::proto::nbns` + technique `nbns` |
| `SMBNameService.swift` | `core::proto::smb` + technique `smb` |
| `LLMNRService.swift` | `core::proto::dns` (builder/parser DNS partagé) + technique `llmnr` |
| `SNMPService.swift` | `core::proto::snmp` (BER fait main, borné) + technique `snmp` |
| `WebServiceIdentifier.swift` | `core::proto::http_title` (extraction) + technique `web_title` (reqwest, TLS non vérifié) |
| `BonjourDiscoveryService.swift` | `core::resolve::discovery::bonjour` (crate `mdns-sd`) |
| `SSDPDiscoveryService.swift` | `core::resolve::discovery::ssdp` |
| `UDPPortScanner.swift` | `core::net::udp_scan` |
| `NmapService.swift` | `core::tools::nmap` (tokio::process, args en tableau, `-Pn -sV -oX -`, kill à l'annulation) |
| `TracerouteService.swift` | `core::tools::traceroute` (exécution via commande fournie par `platform`) + `core::parsers::traceroute` (Unix + `tracert`) |
| `WakeOnLanService.swift` | `core::net::wol` |
| `FavoritesStore`, `VendorOverrideStore`, `SiteProfileStore`, `NetworkProfileStore`, `ScanHistoryService`, `PersistedJSONFile` | `core::store` (JSON atomique, version de schéma, quarantaine, débounce) ; chemin via `directories` dans `patchprobe-app` |
| `CSVExportService`, `JSONExportService`, `HTMLExportService` | `core::export` |
| `NetworkConfigService.swift` | `platform::netconfig` (trait, « non supporté » en v1) |
| `SingleResumer.swift` | inutile (tokio `select!` / `timeout`) |

### ViewModels / Views
| Swift | Rust / TS |
|---|---|
| `ScanViewModel.swift` | `core::engine` (pipeline par hôte, streaming via `mpsc`) + `app/src-tauri` (commandes, état, génération de scan) |
| `AppUIState.swift` | état React (`app/src/state`) |
| `ContentView.swift` | `app/src/components/Toolbar.tsx` |
| `ResultsTableView.swift` | `app/src/components/ResultsTable.tsx` |
| `HostDetailView.swift` | `app/src/components/HostDetail.tsx` (dont panneau « Diagnostic du nom ») |
| `HistoryView.swift`, `ScanDiffView.swift` | `app/src/components/History.tsx` |
| `SiteProfilesView.swift`, `SiteProfileDiffView.swift` | `app/src/components/SiteProfiles.tsx` |
| `SettingsView.swift` | `app/src/components/Settings.tsx` |
| `NetworkConfigView.swift`, `MenuBarContentView.swift` | hors périmètre v1 (trait plateforme « non supporté ») |

## 2. Comportements à reproduire

### Plages et ports
- Plage : CIDR (`/24` exclut réseau et broadcast, `/31` et `/32` incluent tout), plage complète
  `a.b.c.d-e.f.g.h`, plage courte `a.b.c.d-N` (remplace le dernier octet), IP unique. Entrée trimée.
  Plage inversée → erreur. **Plafond** : 65 536 adresses (un /16) vérifié sur les bornes avant
  toute matérialisation.
- Ports : port seul, plage `a-b`, liste séparée par virgules mélangeant les deux ; ports 1..=65535 ;
  dédoublonnés et triés ; plafond 5000 ports au total. Si le champ est vide → liste par défaut
  (`PortScanner.defaultPorts`). Erreurs explicites en Rust (la version Swift retombait
  silencieusement sur la liste par défaut quand la saisie était invalide — on affiche l'erreur).
- `scan_range_text` d'une interface : `192.0.2.1-254` si tient dans un octet, sinon forme complète ;
  `/32` → l'adresse seule.

### Pipeline de scan (par hôte)
1. Statut `scanning`.
2. Ping **et** scan TCP lancés en parallèle (pas de sonde de présence bloquante).
3. Vivant = ping OK **ou** au moins un port ouvert.
4. Mort → statut `down`, compteur incrémenté.
5. Vivant → lookup ARP ciblé immédiat (entrée fraîche), en parallèle de la résolution de nom.
6. Nom : PTR système ∥ DNS de la passerelle (préféré au PTR) ; sinon (et pas de cache) chaîne de
   secours mDNS/NBNS/SMB/LLMNR/SNMP en parallèle puis titre web si ports ouverts ; sinon valeur en cache.
   Les noms trouvés sont mis en cache.
7. Hôte mis à jour : latence, MAC, fabricant (OUI + correction manuelle par MAC), routé (TTL),
   OS probable (TTL), ports.
- Fin de scan : balayage ARP complet (promotion `down`→`up` si présent dans ARP, puis résolution de
  nom pour les promus) ; 2e passe : re-ping des hôtes vivants sans MAC puis relecture ARP.
- Si découverte active : Bonjour puis SSDP, uniquement pour les hôtes vivants sans nom.
- Sauvegarde automatique dans l'historique (hôtes `up` uniquement).
- Scan de plus d'une adresse sans aucun hôte actif → message d'avertissement (pare-feu/permissions).
- Un nouveau scan annule le précédent (génération) ; résultats tardifs ignorés.
- Concurrence Swift : 64 hôtes, 32 ports/hôte. Rust : plafond **global** de connexions TCP (256 par
  défaut) partagé par tous hôtes/ports + plafond d'hôtes ; budget séparé pour la résolution de nom ;
  backoff sur EMFILE/ENOBUFS/ENOMEM.

### TTL → OS / routé
- Plafonds 64 (Linux/macOS), 128 (Windows), 255 (Équipement réseau) ; plafond = premier ≥ TTL.
- Routé ⇔ TTL < plafond. Sans TTL : non routé, OS inconnu.

### Résolution de nom (détail des techniques)
- **PTR** : `getnameinfo` (Rust : `dns-lookup::lookup_addr` dans `spawn_blocking`, borné par timeout).
- **DNS passerelle** : requête PTR `d.c.b.a.in-addr.arpa` envoyée à `passerelle:53`, ignorée si
  cible = passerelle.
- **mDNS** (remplace CFHost) : requête PTR unicast vers l'hôte sur 5353.
- **NBNS** : NBSTAT `*` sur UDP/137 ; parse la 1re entrée (15 octets, trim espaces) ; exige pointeur
  de compression dans le NAME de la réponse.
- **SMB2** : Negotiate (2.0.2, 2.1) puis SessionSetup avec NTLMSSP NEGOTIATE (flags `0xA0888205`) ;
  lit le CHALLENGE, AV_PAIR 1 (NetBIOS) sinon 3 (DNS) en UTF-16LE ; framing NBSS 4 octets, longueur
  < 1 Mo.
- **LLMNR** : même paquet PTR que la passerelle, unicast vers l'hôte UDP/5355 ; décodage de nom
  avec pointeurs de compression, garde anti-boucle (128 sauts).
- **SNMP** : SNMPv1 GetRequest community `public`, OID sysName ; réponse GetResponse (0xA2),
  valeur OCTET STRING ; longueurs BER longues ≤ 4 octets.
- **Titre web** : ports prioritaires (8123, 8006, 32400…) puis les autres ; https pour
  443/8443/9443/4443/8006/10000 ; TLS non vérifié ; statut < 500 ; 8 Ko max ; `<title …>` insensible
  à la casse, entités de base décodées, trim.
- **Bonjour** (fin de scan) : browse des types `_device-info._tcp`, `_airplay._tcp`… ; nettoyage
  du nom (préfixe hex 12 caractères + `@`, suffixe ` [mac]`).
- **SSDP** (fin de scan) : M-SEARCH `ssdp:all` sur 239.255.255.250:1900, en-tête `LOCATION`, puis
  `<friendlyName>` du descripteur XML.
- Nouveauté Rust : chaque technique retourne `Found(nom) | NotFound | Timeout | Error(msg)` avec sa
  durée ; trace complète conservée par hôte pour le panneau **Diagnostic du nom**.
- Cache : par IP, TTL et taille bornée (5000, éviction des plus anciens) ; les échecs ne sont mis
  en cache que quelques minutes.

### Analyse par hôte
- Nmap : recherche dans PATH + chemins connus (`/opt/homebrew/bin`, `/usr/local/bin`,
  `C:\Program Files (x86)\Nmap`…) ; args `-Pn -sV -T4 --version-intensity 2 -oX - <ip>` ; durée
  max 45 s ; tué à l'annulation ; parse `<port protocol portid>`, `<state state>`,
  `<service name product version>` ; port sans `<state>` ignoré ; résumé = service+produit+version.
- UDP : ports 53, 67, 69, 123, 137, 161, 500, 1900, 5353 ; sondes DNS (NS racine), NTP v4 client,
  SNMP sysDescr, sinon 1 octet nul ; réponse → ouvert, ECONNREFUSED → fermé, sinon ouvert|filtré.
- SNMP walk : sysDescr, sysUpTime (formaté `j/h/min`), sysContact, sysName, sysLocation, ifNumber.
- Traceroute : `traceroute -n -q 1 -w 1 -m 30` (Unix) / `tracert -d -h 30 -w 1000` (Windows) ;
  lignes `*` → saut sans adresse ; bannière ignorée ; lignes invalides ignorées.
- Wake-on-LAN : 6×0xFF + 16×MAC vers 255.255.255.255:9 ; MAC `:` ou `-`, 6 octets hex sinon rejet.
- Favoris + note libre par IP.
- URL navigateur : https si 443 ouvert, sinon http si 80, sinon premier port ouvert, sinon http ;
  schéma https pour 443/8443/9443/4443 ; port par défaut omis.

### Persistance / export
- Fichiers JSON : favoris, corrections fabricant (clé MAC en minuscules ; valeur vide = suppression),
  profils de site, réglages, cache de résolution, historique (un fichier par scan, plus récent en
  premier ; entrées dupliquées tolérées).
- Écriture atomique ; fichier corrompu mis en quarantaine (`nom.corrupted-<horodatage>.json`).
- CSV : en-tête `IP,Statut,Hostname,Latence(ms),Ports ouverts,MAC,Fabricant` ; statut « En ligne /
  Hors ligne / Scan en cours / Inconnu » ; latence arrondie ; ports séparés par `;` ; neutralisation
  de formule par `'` (Rust : `= + - @`, tabulation, CR **et espace**) ; quoting RFC 4180.
- JSON : tableau d'objets `ip, status(up/down/scanning/unknown), hostname, latencyMs, openPorts,
  mac, vendor, probableOS, isLikelyRouted`, clés triées.
- HTML : rapport autonome, tout champ échappé (`& < > " '`).

### Diff
- ScanDiff : snapshots ordonnés par date quel que soit l'ordre d'appel ; catégories nouveau / disparu /
  modifié / inchangé, triées dans cet ordre puis IP ; changements « nom : a → b », « MAC : … »,
  « fabricant : … », « ports : +443 -22 ».
- SiteProfileDiff : matching MAC prioritaire (insensible à la casse) ; MAC trouvée + IP différente →
  Écart « IP : x → y » ; entrée sans MAC → matching IP ; entrée avec MAC introuvable → Manquant même si
  son IP est occupée ; hôtes non réclamés → Inattendus.

### Groupement / table
- Sous-réseau (`a.b.c.0/24`, groupes triés par IP), fabricant (alphabétique, « Fabricant inconnu »
  en dernier), statut (Actif, Scan en cours, Inconnu, Inactif). Libellés de statut : Actif / Inactif /
  Scan en cours / Inconnu.
- Classification DeviceType : ordre téléphone (hostname) → caméra (fabricant/554) → imprimante
  (fabricant/631/9100) → NAS → média → IoT → routeur → OS réseau → ordinateur → inconnu.

## 3. Tests Swift à traduire (vecteurs de test)

Priorité 1 — parseurs et services purs (traduits dans `patchprobe-core`) :
| Test Swift | Test Rust |
|---|---|
| `ScanRangeTests` | `core::range::tests` |
| `ScanViewModelHelperTests` (parsePorts, parsePortRange, scheme/url/browserURL) | `core::ports::tests`, `core::model::host::tests` |
| `PortPresetTests` | `core::ports::tests` |
| `ScanSettingsTests` | `core::settings::tests` |
| `HostTests`, `HostGroupingTests` | `core::model::{host,grouping}::tests` |
| `DeviceTypeClassifierTests` | `core::model::device_type::tests` |
| `OUIVendorDatabaseTests` | `core::oui::tests` |
| `ScanDiffTests`, `SiteProfileDiffTests`, `SiteProfileTests` | `core::diff::tests` |
| `PingResultTests` | `core::parsers::ping::tests` (+ fixtures macOS/Linux/Windows, sortie FR) |
| `TracerouteServiceTests` | `core::parsers::traceroute::tests` (+ `tracert`) |
| `NmapXMLParserTests` | `core::parsers::nmap::tests` |
| `SNMPServiceTests` | `core::proto::snmp::tests` (+ buffers malformés / fuzz léger) |
| `NBNSServiceTests` | `core::proto::nbns::tests` |
| `LLMNRServiceTests`, `GatewayDNSResolverTests` | `core::proto::dns::tests` (+ serveur DNS loopback) |
| `WebServiceIdentifierTests` | `core::proto::http_title::tests` |
| `BonjourNameCleanupTests` | `core::resolve::discovery::tests` |
| `UDPPortScannerTests` | `core::net::udp_scan::tests` (+ loopback ouvert/fermé) |
| `WakeOnLanServiceTests` | `core::net::wol::tests` |
| `NetworkInterfaceInfoTests` | `core::range::tests` |
| `CSVExportServiceTests`, `JSONExportServiceTests`, `HTMLExportServiceTests` | `core::export::tests` |

Priorité 2 — stores (sur répertoire temporaire, `tempfile`) :
`ResolutionCacheTests`, `FavoritesStore`, `VendorOverrideStoreTests`, `SiteProfileStoreTests`,
`ScanViewModelRecentRangesTests` → `core::store::tests`, `core::resolve::cache::tests`.

Hors périmètre v1 : `NetworkConfigServiceTests`, `NetworkProfileTests` (configuration IP).

Tests supplémentaires propres au portage : plafond global de connexions (compteur d'accès
simultanés sur serveur loopback), annulation (tous les sockets fermés, processus tué), streaming
des événements, port ouvert = présence sans ping, budget de résolution séparé, cache TTL des échecs.

## 4. État du portage

| Phase | État | Contenu |
|---|---|---|
| 0 — Cartographie | ✅ | ce document |
| 1 — Workspace et modèles | ✅ | 3 crates, ScanRange, ports, presets, OUI, DeviceType, ScanDiff, SiteProfile(Diff) |
| 2 — Moteur de scan | ✅ | plafond TCP global, budget de résolution séparé, backoff EMFILE/ENOBUFS/ENOMEM, annulation, streaming |
| 3 — Résolution de nom | ✅ | 9 techniques + Bonjour/SSDP, trace typée par technique, cache TTL (échecs 5 min) |
| 4 — Analyse par hôte | ✅ | nmap (-Pn -sV, XML), UDP, walk SNMP, traceroute/tracert/tracepath, WoL, favoris/notes |
| 5 — Persistance et export | ✅ | JSON atomique versionné, quarantaine, débounce, historique, CSV/JSON/HTML |
| 6 — Couche plateforme | ✅ | trait `Platform` (interface, passerelle, ARP, ping, navigateur), fixtures 3 OS |
| 7 — Application Tauri | ✅ | commandes + événements regroupés, interface française complète |
| CI | ✅ | `.github/workflows/ci.yml` : macOS, Windows, Ubuntu — npm ci/build, cargo build/test/clippy (`-D warnings`) |

Tests : 196 (186 cœur, 10 plateforme). Clippy vérifié localement pour Linux et la cible
`x86_64-pc-windows-gnu` ; macOS uniquement par la CI.

`NSLocalNetworkUsageDescription` (et `NSBonjourServices`) sont déclarés dans
`app/src-tauri/Info.plist`, fusionné par Tauri (`bundle.macOS.infoPlist`).

## 5. Ce qui reste

- **Jamais exécuté sur un vrai LAN ni lancé graphiquement** : à valider à la main sur les trois OS
  (en particulier le ping Windows localisé, `arp -a`, la détection de passerelle, Bonjour via
  `mdns-sd`, et le dialogue de permission « Réseau local » de macOS).
- **Hors périmètre v1** (signatures seulement dans `Platform`) : configuration IP DHCP/statique,
  profils IP statiques, icône de barre des menus / menu « IP rapide ».
- **Packaging** : non configuré dans la CI (pas de signature, notarisation ni installeurs).
- Raccourcis clavier (⌘↩ / ⌘R de la version Swift) non repris ; menu « Scan rapide » remplacé
  par la liste des plages récentes du champ Plage et le bouton « Ce réseau ».
- Tests Swift non traduits : `NetworkConfigServiceTests`, `NetworkProfileTests` (hors
  périmètre), `GatewayDNSResolverTests.testDetectedGatewayLooksLikeAnIPv4Address` (dépend de la
  machine ; remplacé par les fixtures de `parsers::route`).
- Pas de tests de l'interface React (validation = `tsc` + build Vite).
