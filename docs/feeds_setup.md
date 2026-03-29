# Feeds & Data Sources

## Vercel Cron Feeds

All cron endpoints require `Authorization: Bearer $CRON_SECRET` header.

| Feed | Endpoint | Schedule | What it does | Records/run |
|------|----------|----------|-------------|-------------|
| **OTX** | `POST /api/cron/ingest-otx` | Every 12h | AlienVault OTX pulses → threat_reports + ioc_entries + report_techniques + technique_iocs | ~50-200 reports, ~500+ IOCs |
| **RSS** | `POST /api/cron/ingest-rss` | Every 6h | DFIR Report, Unit42, Microsoft Security, Talos → threat_reports + report_techniques | ~50 reports |
| **abuse.ch** | `POST /api/cron/ingest-abuse-ch` | Daily 2am UTC | ThreatFox + MalwareBazaar → ioc_entries + technique_iocs | ~500+ IOCs |
| **CISA KEV** | `POST /api/cron/ingest-cisa-kev` | Daily 3am UTC | Known Exploited Vulnerabilities → cve_details (is_kev=true) | ~1500 CVEs |
| **NVD Enrich** | `POST /api/cron/enrich-nvd` | Every 4h | CVSS scores, CWE, descriptions for CVEs → cve_details | 20/batch (6s delay without API key) |
| **VT Enrich** | `POST /api/cron/enrich-vt` | Every 8h | VirusTotal sandbox verdicts → ioc_entries (vt_* fields) | 10/batch (rate limited) |
| **D3FEND** | `POST /api/cron/sync-d3fend` | Monthly 1st | MITRE D3FEND defensive mappings → defensive_mappings | ~5000 mappings |
| **CVE Delta** | `POST /api/cron/ingest-cve-delta` | Daily 4am UTC | NVD API last 48h → cve_details + cve_weaknesses + applications + affected_products, refreshes MV | ~50-300 CVEs/day |

## GitHub Actions Feeds

Triggered via GitHub Actions (not Vercel cron). Require `DATABASE_URL` secret in GitHub repo settings.

| Feed | Workflow | What it does | Records |
|------|----------|-------------|---------|
| **Sigma** | `.github/workflows/sync-sigma.yml` | Clones SigmaHQ repo, parses YAML rules → sigma_rules | ~3100 rules |
| **Atomic Red Team** | `.github/workflows/sync-atomic.yml` | Clones atomic-red-team repo, parses YAML → atomic_tests | ~1770 tests |

## Node Scripts (manual)

Run with `DATABASE_URL=... node scripts/<script>.mjs`

### Core Data Scripts

| Script | What it does | Tables affected | Records |
|--------|-------------|-----------------|---------|
| `sync-frameworks.mjs` | NIST 800-53 + Engage + RE&CT + VERIS + Azure + GCP + CAPEC bridge | nist_controls, engage_mappings, react_actions, veris_mappings, cloud_control_mappings, capec_mappings | ~14,000 |
| `sync-thaicert.mjs` | ETDA/ThaiCERT threat actors | external_actors | 514 |
| `sync-capec-bridge.mjs` | CWE→CAPEC→ATT&CK bridge for CVE→technique linking | capec_mappings | ~1,480 |
| `sync-detection-strategies.mjs` | CAR detection strategies + analytics | detection_strategies, detection_analytics | ~691 strategies, ~1,739 analytics |

### ATLAS Domain Scripts

| Script | What it does | Tables affected | Records |
|--------|-------------|-----------------|---------|
| `sync-atlas.mjs` | MITRE ATLAS YAML → tactics, techniques, mitigations, xrefs. Uses js-yaml JSON_SCHEMA (safe). Transaction-wrapped. | tactics, techniques, mitigations, atlas_xrefs | 16 tactics, 155 techniques, 35 mitigations, 34 xrefs |

### CVE & Application Scripts

| Script | What it does | Tables affected | Records |
|--------|-------------|-----------------|---------|
| `ingest-cvelistv5.mjs` | Bulk ingest from CVElistV5 zip. Only onboards CVEs with CWE→CAPEC→technique path. Creates applications, affected_products, refreshes MV. | cve_details, cve_weaknesses, applications, affected_products, app_technique_groups (MV) | ~21K CVEs, ~11K apps, ~80K products |
| `sync-ctid-cve-mappings.mjs` | CTID hand-curated CVE→ATT&CK direct mappings. Creates synthetic CWE entries (CTID-T1190 format) so MV chain works. Also links technique_iocs. | capec_mappings, cve_weaknesses, technique_iocs | ~45 CTID mappings, ~350 direct links |
| `enrich-cve-products.mjs` | Fills affected_products for CVEs missing CPE data (e.g. OTX/CISA CVEs). Fetches from CVElistV5 GitHub API. Refreshes MV. | applications, affected_products, cve_weaknesses, app_technique_groups (MV) | ~750 products added |

#### Usage Examples

```bash
# Bulk CVE ingestion from downloaded zip (run locally, ~5 min)
DATABASE_URL="postgresql://..." node scripts/ingest-cvelistv5.mjs ~/Downloads/cvelistV5-main.zip 2017

# CTID hand-curated mappings (run after CVE ingestion)
DATABASE_URL="postgresql://..." node scripts/sync-ctid-cve-mappings.mjs

# Enrich CTID CVEs missing affected_products
DATABASE_URL="postgresql://..." node scripts/enrich-cve-products.mjs --ctid-only

# Enrich ALL CVEs missing affected_products
DATABASE_URL="postgresql://..." node scripts/enrich-cve-products.mjs

# ATLAS domain sync
DATABASE_URL="postgresql://..." node scripts/sync-atlas.mjs
```

### Sigma / Atomic (local alternatives)

| Script | What it does |
|--------|-------------|
| `sync-sigma.mjs` | Same as GH Action but requires local `/tmp/sigma/rules/` clone |
| `sync-atomic.mjs` | Same as GH Action but requires local clone |

## Python Seed (manual)

```bash
# Seed all 4 domains (enterprise, ics, mobile, atlas)
python seed/seed.py --update                    # local DB
python seed/seed.py --update --confirm-destructive  # production DB (requires DATABASE_URL)
```

**WARNING:** Seed runs `TRUNCATE CASCADE` — wipes ALL data including feed tables. Re-run all feeds after seeding.

## Data Flow: CVE → Application → Technique Chain

```
CVElistV5 zip ──→ cve_details + cve_weaknesses + affected_products + applications
                        │                │
CISA KEV cron ──→ cve_details (is_kev)   │
                                         │
OTX/abuse.ch ──→ ioc_entries ──→ technique_iocs
                                         │
CTID mappings ──→ cve_weaknesses (synthetic CTID-Txxxx CWE)
                  capec_mappings (CTID-DIRECT)
                                         │
                  ┌──────────────────────┘
                  ▼
           capec_mappings (CWE→CAPEC→technique)
                  │
                  ▼
         app_technique_groups (materialized view)
         = affected_products ⨝ cve_weaknesses ⨝ capec_mappings ⨝ techniques ⨝ group_techniques ⨝ threat_groups
         (~1.4M rows, refreshed by ingestion scripts)
```

## Post-Seed Feed Restoration Order

After a full reseed, restore feeds in this order:

1. `node scripts/sync-thaicert.mjs` — ETDA actors (fast, ~30s)
2. `node scripts/sync-frameworks.mjs` — NIST/Engage/RE&CT/VERIS/Cloud/CAPEC (fast, ~60s)
3. `node scripts/sync-detection-strategies.mjs` — Detection strategies + analytics (~30s)
4. `node scripts/sync-atlas.mjs` — ATLAS domain (fast, ~10s)
5. Trigger cron: `/api/cron/ingest-rss` — reports (fast, ~10s)
6. Trigger cron: `/api/cron/ingest-abuse-ch` — IOCs (fast, ~15s)
7. Trigger cron: `/api/cron/ingest-cisa-kev` — CVEs (fast, ~10s)
8. Trigger cron: `/api/cron/ingest-otx` — OTX reports+IOCs (slow, ~60s)
9. Trigger cron: `/api/cron/sync-d3fend` — D3FEND (fast, ~30s)
10. Trigger GH Action: `sync-sigma.yml` — Sigma rules
11. Trigger GH Action: `sync-atomic.yml` — Atomic tests
12. `node scripts/ingest-cvelistv5.mjs <zip> 2017` — CVElistV5 bulk (slow, ~5 min)
13. `node scripts/sync-ctid-cve-mappings.mjs` — CTID mappings (fast, ~30s)
14. `node scripts/enrich-cve-products.mjs` — Enrich missing products (~2 min)

## API Rate Limits

| External API | Limit | Our config |
|-------------|-------|------------|
| NVD (no API key) | 5 req / 30s | 6s delay between requests |
| NVD (with API key) | 50 req / 30s | 1s delay |
| VirusTotal (free) | 4 req/min, 500/day | 10/batch per cron run |
| OTX | No published limit | 10 pulses/run |
| abuse.ch | No published limit | Full feed per run |
| CVElistV5 GitHub raw | No published limit | 5 req/s (self-throttled) |

## Environment Variables

### Required (Vercel)
- `DATABASE_URL` — Neon PostgreSQL connection string
- `CRON_SECRET` — Bearer token for cron endpoints
- `OTX_API_KEY` — AlienVault OTX API key
- `ABUSE_CH_AUTH_KEY` — abuse.ch ThreatFox/MalwareBazaar key
- `VT_API_KEY` — VirusTotal API key

### Optional
- `NVD_API_KEY` — NVD API key (faster enrichment: 1s vs 6s delay)
- `ALLOWED_ORIGIN` — CORS origin override

## Database Tables (Current Counts)

### Seed Data (ATT&CK core — 4 domains)

| Table | Source | Rows |
|-------|--------|------|
| `techniques` | ATT&CK STIX + ATLAS | ~1,249 |
| `tactics` | ATT&CK STIX + ATLAS | 56 |
| `threat_groups` | ATT&CK STIX | 191 |
| `attack_software` | ATT&CK STIX | 914 |
| `campaigns` | ATT&CK STIX | 56 |
| `sectors` | ATT&CK STIX | 12 |
| `data_sources` | ATT&CK STIX | — |
| `mitigations` | ATT&CK STIX + ATLAS | — |
| `atlas_xrefs` | ATLAS YAML | 34 |

### Feed Data

| Table | Source | Rows |
|-------|--------|------|
| `threat_reports` | OTX, RSS | ~80 |
| `report_techniques` | OTX, RSS | ~500+ |
| `ioc_entries` | OTX, abuse.ch | ~5,840 |
| `technique_iocs` | OTX, abuse.ch, CAPEC, CTID | ~26,800 |
| `sigma_rules` | SigmaHQ | ~3,105 |
| `atomic_tests` | Atomic Red Team | ~1,773 |
| `defensive_mappings` | D3FEND | ~5,036 |
| `detection_strategies` | CAR | ~691 |
| `detection_analytics` | CAR | ~1,739 |
| `external_actors` | ThaiCERT/ETDA | 514 |

### Framework Mappings

| Table | Source | Rows |
|-------|--------|------|
| `nist_controls` | NIST 800-53 | ~5,264 |
| `engage_mappings` | MITRE Engage | ~1,113 |
| `react_actions` | RE&CT | 216 |
| `veris_mappings` | VERIS (CTID) | ~1,092 |
| `cloud_control_mappings` | Azure + GCP (CTID) | ~1,454 |
| `capec_mappings` | CAPEC STIX + CTID | ~1,483 |

### CVE & Application Data

| Table | Source | Rows |
|-------|--------|------|
| `cve_details` | CVElistV5, CISA KEV, NVD, OTX | ~21,232 |
| `cve_weaknesses` | CVElistV5, CTID | ~27,046 |
| `applications` | CVElistV5 (CPE data) | ~10,950 |
| `affected_products` | CVElistV5 | ~79,648 |
| `app_technique_groups` | Materialized view (MV) | ~1,407,851 |

### Materialized View

`app_technique_groups` connects applications → CVEs → CWEs → CAPEC → techniques → groups. Refreshed automatically by `ingest-cvelistv5.mjs`, `sync-ctid-cve-mappings.mjs`, and `enrich-cve-products.mjs`.

```sql
-- Manual refresh
REFRESH MATERIALIZED VIEW app_technique_groups;
```

## Full Database Restoration After Truncate

When `seed.py` runs, it `TRUNCATE CASCADE`s all entity tables, wiping feed data too. Here's the full restoration procedure:

### Step 1: Seed ATT&CK data (all 4 domains)

```bash
DATABASE_URL="postgresql://..." python seed/seed.py --update --confirm-destructive
```

Expected output: ~1,249 techniques, 56 tactics, 191 groups, 914 software across Enterprise + ICS + Mobile + ATLAS.

### Step 2: Restore local scripts (run sequentially)

```bash
export DATABASE_URL="postgresql://..."

# ETDA actors (~30s)
node scripts/sync-thaicert.mjs

# NIST 800-53, MITRE Engage, RE&CT, VERIS, Cloud, CAPEC bridge (~60s)
node scripts/sync-frameworks.mjs

# Detection strategies + analytics (~30s)
node scripts/sync-detection-strategies.mjs

# ATLAS domain (~10s)
node scripts/sync-atlas.mjs

# CAPEC bridge standalone (if not done by sync-frameworks) (~10s)
node scripts/sync-capec-bridge.mjs
```

### Step 3: Trigger Vercel cron feeds (need CRON_SECRET)

```bash
export CRON="your-production-cron-secret"
export BASE="https://mitre-explorer.org/api/cron"

# RSS reports — fast (~10s)
curl -s -X POST "$BASE/ingest-rss" -H "Authorization: Bearer $CRON"

# abuse.ch IOCs — fast (~15s)
curl -s -X POST "$BASE/ingest-abuse-ch" -H "Authorization: Bearer $CRON"

# CISA KEV CVEs — fast (~10s)
curl -s -X POST "$BASE/ingest-cisa-kev" -H "Authorization: Bearer $CRON"

# D3FEND mappings — fast (~30s)
curl -s -X POST "$BASE/sync-d3fend" -H "Authorization: Bearer $CRON"

# OTX reports + IOCs — slow, run multiple times (3 pulses per batch)
curl -s -X POST "$BASE/ingest-otx" -H "Authorization: Bearer $CRON"
# Wait 60s, repeat 3-5 times to catch up
```

### Step 4: Trigger GitHub Actions

Using gh CLI at `/Users/peripan/dev/gh_CLI/bin/gh`:

```bash
GH=/Users/peripan/dev/gh_CLI/bin/gh
REPO=PerIPan/mitre-explorer-plus

# Sigma rules (~3100 rules, takes ~2-3 min)
$GH workflow run sync-sigma.yml --repo $REPO

# Atomic Red Team tests (~1770 tests, takes ~2-3 min)
$GH workflow run sync-atomic.yml --repo $REPO

# Check status
$GH run list --repo $REPO --limit 5
```

### Step 5: CVE & Application data (slow)

```bash
export DATABASE_URL="postgresql://..."

# Bulk CVE ingestion from zip (~5 min, requires downloaded zip)
node scripts/ingest-cvelistv5.mjs ~/Downloads/cvelistV5-main.zip 2017

# CTID hand-curated CVE→technique mappings (~30s)
node scripts/sync-ctid-cve-mappings.mjs

# Enrich CVEs missing affected_products (~2 min)
node scripts/enrich-cve-products.mjs
```

### Step 6: Wait for scheduled enrichment

These run automatically via Vercel cron and don't need manual triggering:

- **NVD enrichment** (every 4h) — adds CVSS scores to CVEs, 20 per batch
- **VT enrichment** (every 8h) — adds VirusTotal verdicts to IOCs, 10 per batch
- **OTX** (every 12h) — catches up with more pulses each run

### Step 7: Verify counts

```bash
curl -s https://mitre-explorer.org/api/v1/frameworks/status | python3 -m json.tool
```

### Notes

- OTX is the slowest feed — batches of 3 pulses per run, needs multiple triggers to catch up
- Sigma and Atomic require GitHub Actions (not Vercel cron)
- NVD enrichment without API key uses 6s delay between requests — very slow for large batches
- The `CRON_SECRET` is in Vercel env vars (encrypted). Pull with: `npx vercel env pull`
- CVElistV5 bulk ingestion must be run locally (zip too large for serverless)
- CTID sync should be re-run after any CVElistV5 ingestion to catch newly matched CVEs
- MV refresh is automatic in ingestion scripts; manual refresh: `REFRESH MATERIALIZED VIEW app_technique_groups`

## UI Color Conventions

Entity types have assigned colors — do not change these without explicit approval.

| Entity | Color | CSS vars | Badge variant |
|--------|-------|----------|---------------|
| Technique | Teal | `accent-teal` / `teal-faint` / `teal-dim` | `teal` |
| Group | Orange | `accent-orange` / `orange-faint` / `orange-dim` | `orange` |
| Software | Purple | `accent-purple` / `purple-faint` / `purple-dim` | `purple` |
| Mitigation | Green | `accent-green` / `green-faint` / `green-dim` | `green` |
| Campaign | Blue | `accent-blue` / `blue-faint` / `blue-dim` | `blue` |
| **Data Source** | **Neutral/Gray** | `accent-neutral` / `neutral-faint` / `neutral-dim` | `neutral` |
| Tactic | Yellow | `accent-yellow` / `yellow-faint` / `yellow-dim` | `yellow` |
| Application | Blue | `accent-blue` / `blue-faint` / `blue-dim` | `blue` |
| CVE | Pink | `accent-pink` / `pink-faint` / `pink-dim` | `pink` |
| CWE | Blue | `accent-blue` / `blue-faint` / `blue-dim` | — |
| External Actor | Neutral | `accent-neutral` | `neutral` |

**Important**: Data sources and data components must ALWAYS be neutral/gray — never pink/red. This applies to: EntityLink, ForceGraph NODE_COLORS, SearchBar TYPE_COLORS, Dashboard StatCard, Badge variants in detail pages.
