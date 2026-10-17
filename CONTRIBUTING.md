# Contributing to PatchProbe

Thanks for your interest! Bug reports, fixes and focused improvements are welcome.

The application is the **Rust + Tauri 2** version in [`rust/`](rust/). The original
macOS-only Swift/SwiftUI app (formerly IPScanner) is **not** part of this repository: it is
preserved in the private historical repository and kept only as a behavioral reference. See
[`rust/PORTING.md`](rust/PORTING.md) for the migration overview.

## Prerequisites

| | macOS | Windows | Linux |
|---|---|---|---|
| Rust | stable (via [rustup](https://rustup.rs)) | stable, MSVC toolchain | stable |
| Node.js | 20+ | 20+ | 20+ |
| Build tools | Xcode Command Line Tools | Visual Studio Build Tools (C++) + WebView2 (preinstalled on Windows 10/11) | see below |
| Optional | `nmap` (`brew install nmap`) | `nmap` ([installer](https://nmap.org/download.html)) | `nmap` (package manager) |

**Linux system dependencies for Tauri 2** (Debian/Ubuntu):

```bash
sudo apt-get install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
  librsvg2-dev build-essential libssl-dev patchelf
```

### Permissions needed to scan

- No root/administrator rights are required: PatchProbe uses unprivileged TCP connects,
  UDP sockets and the system `ping`.
- **Linux**: unprivileged `ping` must be allowed (`net.ipv4.ping_group_range`, the default
  on recent distributions). `traceroute` or `tracepath` is needed for the traceroute tool.
- **macOS**: the first scan triggers the *Local Network* permission prompt. If it was
  denied, re-enable it in System Settings › Privacy & Security › Local Network.
- **Windows**: allow the app through Windows Defender Firewall when prompted, otherwise
  some replies (NetBIOS, SSDP, SNMP) are dropped.

## Development

```bash
cd rust/app
npm ci
npm run tauri dev        # run the app with hot reload
npm run build            # build the front-end only (needed once before `cargo build`)
```

Checks (the same ones CI runs on macOS, Windows and Linux):

```bash
cd rust
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Release builds (`npm run tauri build`) need signing credentials only for signed/notarized
packages; see [`.env.example`](.env.example). Never commit certificates, keys or
passwords.

For a Developer ID signed and notarized macOS build, fill `.env` and run
`rust/app/scripts/release-macos.sh` from Terminal.app. The Mac App Store edition
(sandboxed: no MAC addresses, traceroute or nmap) is packaged by
`rust/app/scripts/release-appstore.sh`, which produces a signed `.pkg` for Transporter.

## Conventions

- **Layering**: pure logic, parsers and protocols go in `PatchProbe-core` (no UI, no
  OS-specific code); anything OS-specific goes in `PatchProbe-platform`; Tauri commands and
  events in `rust/app/src-tauri`; UI in `rust/app/src`.
- **Robustness**: no `unwrap`/`expect`/`panic` and no truncating `as` casts outside tests
  (enforced by workspace lints). Network input must be parsed with bounds checks.
- **Tests**: add a test for every parser or behavior change. Use fixtures, never real
  network data: documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
  locally administered MACs (`02:00:00:xx:xx:xx`) and generic names (`printer-01`,
  `nas-01`).
- **UI language**: the interface is in French; code comments may be in French or English.
- Format with `cargo fmt`; keep commits focused, with a clear message.

## Developer Certificate of Origin

By contributing you certify the [Developer Certificate of Origin](https://developercertificate.org/).
Sign off every commit:

```bash
git commit -s -m "Fix NBNS parsing of truncated replies"
```

This adds a `Signed-off-by` line. Use your GitHub-provided noreply address if you do not want
to disclose your personal email. Contributions are accepted under the project's license,
[GPL-3.0](LICENSE).

## Reporting bugs and security issues

Use the issue templates for bugs and feature requests. **Security issues must be reported
privately** — see [SECURITY.md](SECURITY.md). Please redact IP addresses, MAC addresses and
device names from logs and screenshots.
