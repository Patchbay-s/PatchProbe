// Tri, filtre, groupement et formatage de la table (miroir de `HostGrouping.swift`).

import type { DeviceType, GroupingOption, Host, HostStatus, TechniqueId } from "./types";

export type SortKey = "ip" | "status" | "hostname" | "latency" | "os" | "mac" | "vendor" | "ports";
export interface SortState {
  key: SortKey;
  ascending: boolean;
}

export function ipToNumber(ip: string): number {
  const parts = ip.split(".").map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return 0;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

const STATUS_RANK: Record<HostStatus, number> = { up: 0, scanning: 1, unknown: 2, down: 3 };
export const STATUS_LABEL: Record<HostStatus, string> = {
  up: "Actif",
  down: "Inactif",
  scanning: "Scan en cours",
  unknown: "Inconnu",
};

const collator = new Intl.Collator("fr", { numeric: true, sensitivity: "base" });

function compareOptional(a: string | null, b: string | null): number {
  // Valeurs absentes toujours en dernier.
  if (!a && !b) return 0;
  if (!a) return 1;
  if (!b) return -1;
  return collator.compare(a, b);
}

export function compareHosts(a: Host, b: Host, sort: SortState): number {
  let result = 0;
  switch (sort.key) {
    case "ip":
      result = ipToNumber(a.ip) - ipToNumber(b.ip);
      break;
    case "status":
      result = STATUS_RANK[a.status] - STATUS_RANK[b.status];
      break;
    case "hostname":
      result = compareOptional(a.hostname, b.hostname);
      break;
    case "latency":
      result = (a.latencyMs ?? Number.MAX_VALUE) - (b.latencyMs ?? Number.MAX_VALUE);
      break;
    case "os":
      result = compareOptional(a.probableOs, b.probableOs);
      break;
    case "mac":
      result = compareOptional(a.mac, b.mac);
      break;
    case "vendor":
      result = compareOptional(a.vendor, b.vendor);
      break;
    case "ports":
      result = a.openPorts.length - b.openPorts.length;
      break;
  }
  if (result === 0) result = ipToNumber(a.ip) - ipToNumber(b.ip);
  return sort.ascending ? result : -result;
}

/// Recherche en direct sur IP, nom, fabricant, MAC, OS et ports.
export function matchesSearch(host: Host, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const haystack = [
    host.ip,
    host.hostname ?? "",
    host.vendor ?? "",
    host.mac ?? "",
    host.probableOs ?? "",
    host.openPorts.join(" "),
    DEVICE_LABEL[host.deviceType],
  ]
    .join(" ")
    .toLowerCase();
  return q.split(/\s+/).every((term) => haystack.includes(term));
}

export interface HostGroup {
  key: string;
  hosts: Host[];
}

const UNKNOWN_VENDOR = "Fabricant inconnu";

export function subnetKey(ip: string): string {
  const parts = ip.split(".");
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : ip;
}

export function groupHosts(hosts: Host[], option: GroupingOption): HostGroup[] {
  if (option === "none") return [{ key: "", hosts }];
  const buckets = new Map<string, Host[]>();
  for (const host of hosts) {
    const key =
      option === "subnet" ? subnetKey(host.ip) : option === "vendor" ? host.vendor ?? UNKNOWN_VENDOR : STATUS_LABEL[host.status];
    const bucket = buckets.get(key);
    if (bucket) bucket.push(host);
    else buckets.set(key, [host]);
  }
  const groups = [...buckets.entries()].map(([key, list]) => ({ key, hosts: list }));
  if (option === "subnet") {
    groups.sort((a, b) => Math.min(...a.hosts.map((h) => ipToNumber(h.ip))) - Math.min(...b.hosts.map((h) => ipToNumber(h.ip))));
  } else if (option === "vendor") {
    groups.sort((a, b) => {
      if (a.key === UNKNOWN_VENDOR) return 1;
      if (b.key === UNKNOWN_VENDOR) return -1;
      return collator.compare(a.key, b.key);
    });
  } else {
    groups.sort((a, b) => STATUS_RANK[a.hosts[0].status] - STATUS_RANK[b.hosts[0].status]);
  }
  return groups;
}

export const DEVICE_LABEL: Record<DeviceType, string> = {
  router: "Routeur",
  camera: "Caméra",
  printer: "Imprimante",
  phone: "Téléphone/Tablette",
  computer: "Ordinateur",
  nas: "NAS",
  media: "Média/Streaming",
  iot: "Objet connecté",
  networkGear: "Équipement réseau",
  unknown: "Type inconnu",
};

export const DEVICE_ICON: Record<DeviceType, string> = {
  router: "📶",
  camera: "📹",
  printer: "🖨️",
  phone: "📱",
  computer: "🖥️",
  nas: "🗄️",
  media: "📺",
  iot: "💡",
  networkGear: "🔀",
  unknown: "❔",
};

export const TECHNIQUE_LABEL: Record<TechniqueId, string> = {
  cache: "Cache",
  ptr: "PTR (DNS système)",
  gatewayDns: "DNS du routeur",
  mdns: "mDNS",
  nbns: "NetBIOS (NBNS)",
  smb: "SMB2/NTLMSSP",
  llmnr: "LLMNR",
  snmp: "SNMP sysName",
  webTitle: "Titre web",
  bonjour: "Bonjour",
  ssdp: "SSDP/UPnP",
};

export function formatLatency(ms: number | null): string {
  if (ms === null) return "—";
  if (ms < 1) return "<1 ms";
  return `${Math.round(ms)} ms`;
}

export function schemeForPort(port: number): "http" | "https" {
  return [443, 8443, 9443, 4443].includes(port) ? "https" : "http";
}

/// Le port 80/443 ou un port « web » connu : affiché comme raccourci d'ouverture.
export function isWebPort(port: number): boolean {
  return [80, 81, 443, 3000, 5000, 5001, 8000, 8006, 8080, 8081, 8096, 8123, 8181, 8443, 9000, 9091, 9443, 19999, 32400].includes(port);
}

export function formatDate(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString("fr-FR", { dateStyle: "medium", timeStyle: "short" });
}
