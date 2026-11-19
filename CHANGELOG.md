# Changelog

## 3.2.0

- **ndjson output:** `-o ndjson` (or `-r file.ndjson` / `.jsonl`) writes one flat JSON object per
  IOC per line (`ts`, `ioc`, `type`, `verdict`, `flagged`, `queried`, `confidence`, `sources`,
  `reference`, `first_seen`, `techniques`, ...), for shipping scan results to Logstash/Elasticsearch
  with Filebeat. Every IOC is written; filter on `verdict` downstream.
- **Forwarding:** `-forward <url>` (on `scan` and `web`) or `ZUHAN_FORWARD_URL` POSTs every
  lookup, clean ones included, to an HTTP collector such as a Logstash `http` input, as a JSON
  array of `{"zuhan": <ndjson record>, "tags": ["zuhan", "zuhan-cli" | "zuhan-web"]}`. A collector
  error is only a warning (a toast in the web UI); the scan and its exit code are unchanged.
- ndjson records have a new `ioc_type` field: `hash`, `ip`, `domain` or `url`.
- `integrations/elastic`: Logstash pipeline (every lookup to `zuhan-lookups-*`, malicious IOCs as
  ECS `threat.indicator` to `zuhan-ti`), index template, Kibana setup and example detection rules.
- Dockerfile (multi-stage, static binary) and `.dockerignore`.

## 3.1.1

- urlscan.io: URL lookups no longer fail when urlscan returns HTTP 502 for a URL search. Other
  spellings of the query are tried, then the URL's host (marked "host only"; a malicious
  verdict there counts as suspicious).
- ThreatFox: a domain or IP search also returns URLs and ports *on* that host. If only those
  are listed, the result is now suspicious with a "related IOCs" note instead of malicious, and
  their dates no longer trigger NEW (google.com was reported malicious because of abused URLs).
- Allow-listed IOCs (KNOWN BENIGN): a malicious verdict from a single source is now lowered to
  clean as well; two or more sources saying malicious still win.
- ThreatFox summary is shorter (at most 3 malware names and threat types).
- HTTP errors are readable: an HTML error page is no longer dumped into the result, and JSON
  error messages are shown as text.

## 3.1.0

- **New sources:** Triage (tria.ge sandbox: score, family, extracted C2s, signatures),
  urlscan.io, mnemonic passive DNS, RDAP/WHOIS (registrar, dates, network owner; domains
  registered less than 30 days ago are suspicious) and live DNS resolution (opt-in with `-dns`,
  because the lookup can reach the attacker's name server).
- **MISP warninglists** built in: known-benign IOCs are marked KNOWN BENIGN, a suspicious
  verdict on them becomes clean, and they are never auto-added; cloud, Tor, scanner and
  shared-hosting matches get a CONTEXT label. `zuhan warninglists list|check|update|path`.
- **NEW** flag for malicious/suspicious IOCs first reported within `-new-days` (default 7).
- **UNKNOWN** flag for IOCs no intel source has seen.
- **Auto-add threshold:** `-save-min n` (web UI: "when flagged by ≥ n sources").
- **ThreatFox** results now show malware, aliases, Malpedia, threat and IOC type, confidence,
  first/last seen, reporter, reference and tags. Several sources report "first seen".
- **MITRE ATT&CK:** techniques from OTX, Hybrid Analysis and Triage are named, grouped by tactic
  per IOC and per scan, shown in every report format and the web UI, and exportable as an ATT&CK
  Navigator layer (`-attack-layer`, or the web UI button). ATT&CK Enterprise 20.1 is built in.
- `-offline` now checks the warninglists as well as the local list.
- Reports (table, HTML, Markdown, CSV, JSON) include the new flags, labels and techniques.
- Added `NOTICE` with MITRE ATT&CK and MISP warninglists attribution.

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
