// Types miroirs des structures Rust (serde camelCase).

export type HostStatus = "unknown" | "scanning" | "up" | "down";

export type DeviceType =
  | "router"
  | "camera"
  | "printer"
  | "phone"
  | "computer"
  | "nas"
  | "media"
  | "iot"
  | "networkGear"
  | "unknown";

export interface Host {
  ip: string;
  hostname: string | null;
  hostnameSource: string | null;
  status: HostStatus;
  latencyMs: number | null;
  openPorts: number[];
  mac: string | null;
  vendor: string | null;
  vendorOverridden: boolean;
  ttl: number | null;
  isLikelyRouted: boolean;
  probableOs: string | null;
  deviceType: DeviceType;
}

export interface ScanSettings {
  pingTimeoutMs: number;
  portTimeoutMs: number;
  nameTimeoutMs: number;
  webTitleTimeoutMs: number;
  runsActiveDiscovery: boolean;
  runsArpSweep: boolean;
  maxTcpConnections: number;
  maxParallelHosts: number;
  maxParallelNameResolutions: number;
  /** Source du nom affiché quand elle en trouve un ; `null` = ordre automatique. */
  preferredNameSource: TechniqueId | null;
}

export type PortPresetKind = "cameraIP" | "generic" | "webServer" | "printer" | "nas";
export type TimingPreset = "rapide" | "approfondi";
export type GroupingOption = "none" | "subnet" | "vendor" | "status";

export interface AppSettings {
  scan: ScanSettings;
  lastPortPreset: PortPresetKind | null;
  portsInput: string;
  recentRanges: string[];
  hideDownHosts: boolean;
  grouping: GroupingOption;
}

export interface InterfaceInfo {
  name: string;
  ip: string;
  netmask: string;
  prefixLen: number;
}

export interface IpAnnotation {
  favorite: boolean;
  note: string;
  updatedAt: string;
}

export type Annotations = Record<string, IpAnnotation>;

export interface PortPresetInfo {
  kind: PortPresetKind;
  label: string;
  ports: string;
}

export interface Bootstrap {
  settings: AppSettings;
  interface: InterfaceInfo | null;
  defaultRange: string | null;
  gateway: string | null;
  os: string;
  warnings: string[];
  portPresets: PortPresetInfo[];
  defaultPorts: string;
  udpPorts: number[];
  nmapAvailable: boolean;
  nmapHint: string;
  tracerouteAvailable: boolean;
  /** Édition App Store (bac à sable) : pas de MAC ni de fabricant. */
  sandboxed: boolean;
  annotations: Annotations;
  dataDir: string;
  rangeInput: string;
  hosts: Host[];
}

export interface ScanStarted {
  scanId: number;
  total: number;
  portCount: number;
}

export interface ScanStats {
  durationMs: number;
  peakTcpConnections: number;
  resourceExhaustionEvents: number;
  abandonedProbes: number;
}

export type ScanPhase = "hosts" | "arpSweep" | "discovery";

export type ScanEvent =
  | { type: "started"; scanId: number; total: number; portCount: number }
  | { type: "phase"; scanId: number; phase: ScanPhase }
  | { type: "progress"; scanId: number; scanned: number; total: number; up: number }
  | { type: "warning"; scanId: number; message: string }
  | { type: "finished"; scanId: number; cancelled: boolean; up: number; total: number; stats: ScanStats };

export interface HostsBatch {
  scanId: number;
  hosts: Host[];
}

export interface ScanCompleted {
  scanId: number;
  cancelled: boolean;
  up: number;
  historySaved: boolean;
  error: string | null;
}

export type TechniqueId =
  | "cache"
  | "ptr"
  | "gatewayDns"
  | "mdns"
  | "nbns"
  | "smb"
  | "llmnr"
  | "snmp"
  | "webTitle"
  | "bonjour"
  | "ssdp";

export type Outcome =
  | { kind: "found"; detail: string }
  | { kind: "notFound"; detail: string }
  | { kind: "timeout" }
  | { kind: "error"; detail: string }
  | { kind: "skipped"; detail: string };

export interface TechniqueResult {
  technique: TechniqueId;
  outcome: Outcome;
  durationMs: number;
}

export interface NameTrace {
  ip: string;
  results: TechniqueResult[];
  chosen: { name: string; technique: TechniqueId } | null;
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
}

export interface NmapResult {
  report: { ports: NmapPort[]; hostnames: string[]; hostState: string | null };
  rawOutput: string;
  commandLine: string;
}

export type UdpPortStatus = "open" | "closed" | "openOrFiltered";

export interface UdpPortResult {
  port: number;
  service: string | null;
  status: UdpPortStatus;
}

export interface SnmpSystemInfo {
  sysDescr: string | null;
  sysUpTime: string | null;
  sysContact: string | null;
  sysName: string | null;
  sysLocation: string | null;
  ifNumber: number | null;
}

export interface TracerouteHop {
  hop: number;
  address: string | null;
  rttMs: number | null;
}

export interface HistoryEntry {
  id: string;
  date: string;
  rangeInput: string;
  hostCount: number;
}

export interface HostSnapshot {
  ip: string;
  hostname: string | null;
  latencyMs: number | null;
  openPorts: number[];
  mac: string | null;
  vendor: string | null;
}

export type HostChangeKind = "new" | "gone" | "changed" | "unchanged";

export interface HostDiffEntry {
  ip: string;
  kind: HostChangeKind;
  before: HostSnapshot | null;
  after: HostSnapshot | null;
  changes: string[];
}

export interface ScanDiff {
  older: { id: string; date: string; rangeInput: string };
  newer: { id: string; date: string; rangeInput: string };
  entries: HostDiffEntry[];
}

export interface SiteProfileEntry {
  id: string;
  label: string;
  ip: string | null;
  mac: string | null;
}

export interface SiteProfile {
  id: string;
  name: string;
  entries: SiteProfileEntry[];
}

export type SiteProfileMatchKind = "matched" | "mismatch" | "missing" | "unexpected";

export interface SiteProfileDiffEntry {
  id: string;
  kind: SiteProfileMatchKind;
  entry: SiteProfileEntry | null;
  host: Host | null;
  changes: string[];
}

export interface SiteProfileDiff {
  profile: SiteProfile;
  entries: SiteProfileDiffEntry[];
}

export type ExportFormat = "csv" | "json" | "html";
