# PatchProbe — Rust + Tauri 2 (macOS, Windows, Linux)

Application multiplateforme issue de l'ancien projet macOS Swift (`../PatchProbe`).
Voir [PORTING.md](PORTING.md) pour la correspondance fichier Swift → module Rust.

## Architecture

```
rust/
├── crates/patchprobe-core      logique pure et portable (aucune dépendance UI/OS)
│   ├── range, ports, settings      plages (plafond /16), ports, presets
│   ├── model, diff                 Host, DeviceType, groupement, ScanDiff, SiteProfileDiff
│   ├── oui                         base IEEE embarquée (crates/patchprobe-core/resources/OUIVendors.json)
│   ├── engine                      moteur de scan tokio (plafond TCP global, annulation, streaming)
│   ├── resolve                     PTR, DNS routeur, mDNS, NBNS, SMB, LLMNR, SNMP, titre web,
│   │                               Bonjour, SSDP — trace typée par technique, cache TTL
│   ├── proto                       codecs DNS/NBNS/SNMP(BER)/SMB2-NTLMSSP/HTTP/SSDP bornés
│   ├── net                         sonde TCP, scan UDP, walk SNMP, Wake-on-LAN
│   ├── parsers                     sorties ping/arp/route/traceroute/nmap (fixtures 3 OS)
│   ├── store                       JSON atomique versionné, quarantaine, débounce, historique
│   └── export                      CSV (anti-injection), JSON, HTML
├── crates/patchprobe-platform  ce qui dépend de l'OS (trait Platform, sous-processus, dossiers)
└── app/                       Tauri 2 : src-tauri (crate patchprobe-app) + React/TS/Vite
```

## Prérequis

- Rust stable récent (1.80+) et Node.js 20+.
- **Linux** : `libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev build-essential`
  (Debian/Ubuntu). Le ping doit fonctionner sans root (`net.ipv4.ping_group_range`, défaut sur
  les distributions récentes). `traceroute` ou `tracepath` pour le traceroute.
- **macOS** : Xcode Command Line Tools.
- **Windows** : WebView2 (inclus dans Windows 10/11 à jour) et les Build Tools MSVC.
- Optionnel : `nmap` pour le scan approfondi (`brew install nmap`, `apt install nmap`, ou
  l'installateur Windows de nmap.org). Sans nmap, l'app le signale clairement.

## Commandes

```bash
cd rust/app
npm ci
npm run tauri dev      # développement
npm run tauri build    # binaire + installeur de l'OS courant

# Vérifications (le frontend doit avoir été construit une fois : npm run build)
cd rust
cargo build
cargo test
cargo clippy --all-targets
```

## Données

Fichiers JSON (avec `schemaVersion`) dans le dossier de données de l'utilisateur :
macOS `~/Library/Application Support/com.patchbay.patchprobe`, Linux `~/.local/share/patchprobe`,
Windows `%APPDATA%\patchbay\patchprobe\data`. Un fichier illisible est mis de côté
(`*.corrupted-<date>.json`) et jamais écrasé.

## Hors périmètre de cette version

Configuration IP / profils IP statiques et icône de barre des menus : seules les signatures du
trait `Platform` existent (implémentation « non prise en charge »).
