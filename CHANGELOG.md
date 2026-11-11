# Changelog

## 3.0.0

- **Renamed to ZUHAN.** The command is now `zuhan`, the Go module is
  `github.com/DNA-Cybertech-Solutions/zuhan`, release files are `zuhan-<os>-<arch>`, and settings live in
  `~/.config/zuhan`.
- Settings from the old `~/.config/iocscan` folder (API keys and the local IOC list) are copied
  automatically on first run; the old folder is left untouched.
- `ZUHAN_DB` replaces `IOCSCAN_DB` (the old variable still works). Exports made with iocscan
  can still be imported.
- The command line is now fully in English.

## 2.3.0 (as iocscan)

- Web UI translated to English.
- README split into English (`README.md`) and Turkish (`README_TR.md`).
- Repository layout for GitHub: Go module at the root, `Makefile`, CI and release workflows,
  `.gitignore`, screenshots, Windows launcher in `scripts/`.
- Version can be injected at build time (`-ldflags "-X main.version=…"`).

## 2.2.1

- AlienVault OTX: only real allow-lists (whitelist, Alexa, Majestic, known false positive…)
  count as clean. Plain annotations such as "Tor exit node" no longer mark an IOC clean.
- GreyNoise: clearer summary (no more "unknown · Success").
- VirusTotal: a single engine on an IOC with non-negative reputation is reported as clean with
  a "likely false positive" note instead of suspicious (e.g. 8.8.8.8).

## 2.2.0

- API keys can be entered, replaced and deleted from the web UI and take effect immediately.
- Saved keys are never sent back to the browser; only their last 4 characters are shown.

## 2.1.0

- `iocscan web`: a local-only browser UI (scan, dump extraction, file hashing, IOC list
  management, report download), protected by loopback binding, Host checks and a per-run token.

## 2.0.0

- Local IOC list: checked on every scan; malicious results are added automatically.
- `db add/rm/list/import/export/stats/path` commands, including interactive add.
- IOC extraction from dumps (`extract`, `scan -dump`).
- Framework layout: public `pkg/` packages, `Scanner`, `Source` and `Store` interfaces.

## 1.0.0

- First release: parallel lookups in VirusTotal, MalwareBazaar, ThreatFox, URLhaus, OTX,
  Hybrid Analysis, AbuseIPDB, GreyNoise and Shodan InternetDB; table/JSON/Markdown/CSV/HTML
  reports; exit codes.
