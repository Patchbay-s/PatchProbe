> **Obsolete.** This C#/WPF plan was superseded by the cross-platform Rust + Tauri app in
> [`rust/`](../rust/). Kept for reference only.

# Spec — Scanner réseau Windows (équivalent natif de PatchProbe macOS)

## Objectif
Version Windows de l'app PatchProbe existante (macOS, Swift/SwiftUI). Même liste de fonctionnalités,
même usage personnel, mais codebase séparée et réimplémentation native — pas un portage direct
(SwiftUI n'existe pas sous Windows).

## Stack technique recommandée
- **C# / .NET 8+ / WPF** — mature, bien documenté, DPI/multi-écran solides, XAML proche dans l'esprit
  de SwiftUI (binding déclaratif, MVVM). Alternative : **WinUI 3** si tu préfères l'esthétique
  Windows 11 native, mais l'écosystème/tooling est moins mature que WPF pour ce genre d'app.
- **MVVM** (Model-View-ViewModel) — équivalent direct du couple ViewModel/View SwiftUI déjà utilisé
  côté Mac
- Concurrence : `async`/`await` + `SemaphoreSlim` pour borner le parallélisme (équivalent du
  `TaskGroup` borné à 64 hôtes côté Mac)
- Élévation ponctuelle Windows : lancer un sous-processus avec `UseShellExecute = true` et
  `Verb = "runas"` (déclenche l'invite UAC), équivalent de `osascript ... with administrator
  privileges` côté Mac — pas de mot de passe stocké, pas de service séparé installé

## Table d'équivalence des services (macOS → Windows)

| Fonction | macOS (existant) | Windows (à implémenter) |
|---|---|---|
| Ping | `Process` → `/sbin/ping` | `System.Net.NetworkInformation.Ping` (natif .NET, pas besoin de shell out) |
| Scan TCP | `NWConnection` (Network.framework) | `TcpClient.ConnectAsync` avec timeout (`Task.WhenAny` + `Task.Delay`) |
| MAC/ARP | `Process` → `arp -a`/`arp -n` | Parsing de `arp -a` (format différent) ou **IP Helper API** (`GetIpNetTable` via P/Invoke, plus fiable que parser du texte) |
| Fabricant (OUI) | Base IEEE MA-L embarquée (JSON) | Même base OUI réutilisable telle quelle (format indépendant de l'OS) |
| Config réseau | `networksetup` (DHCP/statique) | `netsh interface ip set address` / `netsh interface ip set dns` (nécessite élévation) |
| Nmap | `Process` → `nmap` (Homebrew) | `Process` → `nmap.exe` (installateur Windows officiel), même sortie XML, même parseur réutilisable en logique |
| Traceroute | `Process` → `/usr/sbin/traceroute` | `Process` → `tracert.exe` (syntaxe de sortie différente, à reparser) |
| NetBIOS (NBNS) | Socket UDP fait main | Identique en C# (`UdpClient`), protocole indépendant de l'OS |
| SNMP | BER/ASN.1 fait main | Réutilisable tel quel en C# (le protocole ne change pas), ou bibliothèque NuGet `#SNMP` si tu préfères ne pas réécrire le parsing BER |
| Wake-on-LAN | Paquet magique UDP | Identique — protocole indépendant de l'OS |
| Bonjour/mDNS | `CFHost`/Bonjour natif | `Zeroconf` (NuGet) ou service Bonjour pour Windows si installé, sinon dégrader proprement (mDNS moins universellement supporté sous Windows) |
| SSDP/UPnP | Socket UDP fait main | Identique en C# (`UdpClient`), protocole indépendant de l'OS |
| Persistance JSON | Fichiers dans Application Support | `System.Text.Json` + dossier `%APPDATA%\PatchProbe` |
| Ouverture navigateur | `NSWorkspace.shared.open` | `Process.Start` avec `UseShellExecute = true` sur l'URL |

## Fonctionnalités à reproduire (reprises telles quelles de la version Mac)

### Scan de base
- Saisie de plage CIDR / range / IP unique, auto-détection de la plage locale
- Ping + scan TCP concurrent en parallèle par hôte, port ouvert = preuve de présence même si le ping échoue
- Ports par défaut + plage personnalisable (port seul, plage, liste séparée par virgules)
- Table triable, mise à jour en direct, barre de progression

### Résolution de nom
Même chaîne de secours multi-techniques : PTR → DNS du routeur → mDNS → NBNS → SMB2/NTLMSSP pré-auth
→ LLMNR → SNMP sysName → titre HTML. Cache par IP entre scans.

### Identification des hôtes
MAC via ARP, fabricant via OUI, OS probable via TTL, icône par type d'appareil.

### Analyse approfondie par hôte
Nmap (`-sV`, XML parsé), SNMP walk, scan UDP, traceroute, Wake-on-LAN, favori + note.

### Profils de site
Modèle SiteProfile/SiteProfileEntry, comparaison MAC-prioritaire (Manquants/Inattendus/Écarts/Conformes).

### Presets de ports par type d'appareil
Caméra IP, Générique/Homelab, Serveur web, Imprimante, NAS.

### Historique et export
Sauvegarde JSON, diff entre scans, export CSV/JSON/HTML.

### Configuration réseau
Lecture/écriture DHCP/statique par interface, profils IP nommés.

## Points d'attention spécifiques Windows
- **Pas de sandbox à désactiver** (contrairement à macOS) — mais le **manifeste d'application**
  (`app.manifest`) doit déclarer `requestedExecutionLevel` correctement ; éviter de demander une
  élévation globale au lancement (dégraderait l'UX) — élévation ponctuelle uniquement pour les
  actions de config réseau, via un sous-processus séparé
- **Windows Defender / SmartScreen** : un exécutable non signé déclenchera un avertissement au
  premier lancement, équivalent du Gatekeeper macOS. Pour un usage perso, un simple clic sur
  "Informations complémentaires → Exécuter quand même" suffit ; pas besoin de certificat de
  signature de code Authenticode pour un usage strictement personnel (contrairement à macOS où
  la notarisation est quasi obligatoire même pour soi-même sur une machine différente)
- **Firewall Windows** : au premier scan, Windows demandera probablement d'autoriser l'app sur
  réseaux privés — prévoir cette invite dans le flow de premier lancement, équivalent de
  `NSLocalNetworkUsageDescription` côté Mac
- **`arp -a` change de format** entre Windows et macOS — ne pas réutiliser le parseur Mac tel quel

## Ce qui NE nécessite aucune réécriture
- La base de données OUI (JSON, ~39 688 entrées) — réutilisable telle quelle
- La logique de comparaison SiteProfileDiff (matching MAC-prioritaire) — logique pure, indépendante de l'OS
- Le parsing BER/ASN.1 SNMP fait main — protocole, pas plateforme
- La structure de données Host, ScanRange, PortPreset — portables telles quelles (juste retraduites en C#)
