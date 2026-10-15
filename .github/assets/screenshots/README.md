# Screenshots

The project README shows a shared placeholder until captures are available. Replace each
placeholder reference with the PNG file below after capturing it from the app.

> **Privacy first.** Capture against a demo or lab network, or blur every real IP address,
> MAC address, hostname, Wi-Fi name and vendor before committing. Suggested demo data:
> `192.0.2.0/24` / `198.51.100.0/24` ranges, MACs `02:00:00:xx:xx:xx`, names such as
> `printer-01`, `nas-01`, `camera-01`. Once pushed, an image stays in the git history.

| File | Screen | OS | Suggested size |
|---|---|---|---|
| `hero.png` | Main window after a finished scan: toolbar, progress bar, results table with several live hosts, detail panel open | macOS (light) | 2400 × 1500 (Retina), ≤ 1 MB |
| `discovery.png` | Scan in progress: progress bar and phase, rows appearing live, "Masquer les injoignables" ticked | Windows | 1600 × 1000 |
| `name-diagnostic.png` | Host detail, "Diagnostic du nom" section showing every technique with its result and duration | macOS | 1200 × 1400 (panel crop) |
| `vendors.png` | Table grouped by "Fabricant", one row with a manual vendor override ("modifié" badge) | Linux | 1600 × 1000 |
| `ports.png` | Toolbar with the "Preset ports" menu open, "Ports ouverts" column visible | macOS | 1600 × 600 |
| `host-tools.png` | Host detail with nmap results table, UDP ports and traceroute hops | Windows | 1200 × 1600 (panel crop) |
| `history-diff.png` | History dialog comparing two scans (appeared / gone / changed) | macOS | 1600 × 1000 |
| `site-profiles.png` | Site profile comparison: missing / unexpected / mismatched / matching | Linux | 1600 × 1000 |
| `export.png` | "Exporter" menu open (CSV / JSON / HTML) and an HTML report opened in a browser | macOS | 1600 × 1000 |

Tips: use the same window size for all captures, light theme for the hero, and optimize the
PNGs (e.g. `oxipng -o 4`) before committing.
