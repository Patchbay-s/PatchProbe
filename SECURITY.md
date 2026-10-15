# Security Policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/Patchbay-s/PatchProbe/security/advisories/new)
(“Report a vulnerability” in the repository's *Security* tab). Include:

- the affected version or commit, and your operating system;
- a description of the issue and its impact;
- steps to reproduce or a proof of concept, using **test or documentation addresses**
  (e.g. `192.0.2.0/24`) rather than real network data.

You should get an acknowledgement within a few days. This is a spare-time project
maintained by one person: fixes are best effort, and coordinated disclosure is
appreciated.

## Supported versions

PatchProbe is pre-release. Only the latest commit of the default branch receives fixes.

## Scope

Of particular interest:

- parsing of untrusted network data (DNS, NetBIOS, SNMP/BER, SMB/NTLMSSP, SSDP, HTML,
  nmap XML) leading to crashes or memory/CPU exhaustion;
- command injection through subprocess calls (`ping`, `arp`, `nmap`, `traceroute`…);
- injection in exports (CSV formulas, HTML) or in URLs opened in the browser;
- unsafe handling of the local data directory.

## Responsible use

PatchProbe sends probes (ping, TCP connections, UDP, NetBIOS, SNMP, SMB, HTTP…) to the
machines of the range you scan. **Only scan networks you own or are explicitly authorized
to scan.** Scanning third-party networks can be illegal in many jurisdictions and may
trigger intrusion-detection systems. Reports about using PatchProbe against networks you do
not control are out of scope.
