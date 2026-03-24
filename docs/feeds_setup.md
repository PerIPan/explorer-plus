# Feeds & API Reference

## Vercel Cron Feeds

All cron endpoints require `Authorization: Bearer $CRON_SECRET` header.

| Feed | Endpoint | Schedule | What it does | Records/run |
|------|----------|----------|-------------|-------------|
| **OTX** | `POST /api/cron/ingest-otx` | Every 12h | AlienVault OTX pulses → threat_reports + ioc_entries + report_techniques + technique_iocs | ~50-200 reports, ~500+ IOCs |
| **RSS** | `POST /api/cron/ingest-rss` | Every 6h | DFIR Report, Unit42, Microsoft Security, Talos → threat_reports + report_techniques | ~50 reports |
| **abuse.ch** | `POST /api/cron/ingest-abuse-ch` | Daily 2am UTC | ThreatFox + MalwareBazaar → ioc_entries + technique_iocs | ~500+ IOCs |
| **CISA KEV** | `POST /api/cron/ingest-cisa-kev` | Daily 3am UTC | Known Exploited Vulnerabilities → cve_details | ~1500 CVEs |
| **NVD Enrich** | `POST /api/cron/enrich-nvd` | Every 4h | CVSS scores, CWE, descriptions for CVEs → cve_details | 20/batch (6s delay without API key) |
| **VT Enrich** | `POST /api/cron/enrich-vt` | Every 8h | VirusTotal sandbox verdicts → ioc_entries (vt_* fields) | 10/batch (rate limited) |
| **D3FEND** | `POST /api/cron/sync-d3fend` | Monthly 1st | MITRE D3FEND defensive mappings → defensive_mappings | ~800 mappings |

## GitHub Actions Feeds

Triggered via GitHub Actions (not Vercel cron). Require `DATABASE_URL` secret in GitHub repo settings.

| Feed | Workflow | What it does | Records |
|------|----------|-------------|---------|
| **Sigma** | `.github/workflows/sync-sigma.yml` | Clones SigmaHQ repo, parses YAML rules → sigma_rules | ~3000 rules |
| **Atomic Red Team** | `.github/workflows/sync-atomic.yml` | Clones atomic-red-team repo, parses YAML → atomic_tests | ~1500 tests |

## Node Scripts (manual)

Run with `DATABASE_URL=... node scripts/<script>.mjs`

| Script | What it does |
|--------|-------------|
| `sync-thaicert.mjs` | ETDA/ThaiCERT threat actors → external_actors (514 actors) |
| `sync-frameworks.mjs` | NIST 800-53 + MITRE Engage + RE&CT → nist_controls, engage_mappings, react_actions |
| `sync-sigma.mjs` | Same as GH Action but requires local `/tmp/sigma/rules/` clone |
| `sync-atomic.mjs` | Same as GH Action but requires local clone |

## Python Seed (manual)

```bash
# Seed all 3 domains (enterprise, ics, mobile)
python seed/seed.py --update                    # local DB
python seed/seed.py --update --confirm-destructive  # production DB (requires DATABASE_URL)
```

**WARNING:** Seed runs `TRUNCATE CASCADE` — wipes ALL data including feed tables. Re-run all feeds after seeding.

## Post-Seed Feed Restoration Order

After a full reseed, restore feeds in this order:

1. `node scripts/sync-thaicert.mjs` — ETDA actors (fast, ~30s)
2. `node scripts/sync-frameworks.mjs` — NIST/Engage/RE&CT (fast, ~60s)
3. Trigger cron: `/api/cron/ingest-rss` — reports (fast, ~10s)
4. Trigger cron: `/api/cron/ingest-abuse-ch` — IOCs (fast, ~15s)
5. Trigger cron: `/api/cron/ingest-cisa-kev` — CVEs (fast, ~10s)
6. Trigger cron: `/api/cron/ingest-otx` — OTX reports+IOCs (slow, ~60s)
7. Trigger cron: `/api/cron/enrich-nvd` — NVD enrichment (very slow, batch of 20)
8. Trigger cron: `/api/cron/sync-d3fend` — D3FEND (fast, ~30s)
9. Trigger GH Action: `sync-sigma.yml` — Sigma rules
10. Trigger GH Action: `sync-atomic.yml` — Atomic tests

## API Rate Limits

| External API | Limit | Our config |
|-------------|-------|------------|
| NVD (no API key) | 5 req / 30s | 6s delay between requests |
| NVD (with API key) | 50 req / 30s | 1s delay |
| VirusTotal (free) | 4 req/min, 500/day | 10/batch per cron run |
| OTX | No published limit | 10 pulses/run |
| abuse.ch | No published limit | Full feed per run |

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

## Database Tables (Feed-populated)

| Table | Source | Rows (approx) |
|-------|--------|---------------|
| `threat_reports` | OTX, RSS | ~200+ |
| `report_techniques` | OTX, RSS | ~500+ |
| `ioc_entries` | OTX, abuse.ch | ~1000+ |
| `technique_iocs` | OTX, abuse.ch | ~500+ |
| `cve_details` | CISA KEV, NVD | ~1500+ |
| `sigma_rules` | SigmaHQ | ~3000 |
| `atomic_tests` | Atomic Red Team | ~1500 |
| `defensive_mappings` | D3FEND | ~800 |
| `nist_controls` | NIST 800-53 | ~5300 |
| `engage_mappings` | MITRE Engage | ~1100 |
| `react_actions` | RE&CT | ~216 |
| `external_actors` | ThaiCERT/ETDA | 514 |

## Full Database Restoration After Truncate

When `seed.py` runs, it `TRUNCATE CASCADE`s all entity tables, wiping feed data too. Here's the full restoration procedure:

### Step 1: Seed ATT&CK data (all 3 domains)

```bash
DATABASE_URL="postgresql://..." python seed/seed.py --update --confirm-destructive
```

Expected output: ~1,094 techniques, 40 tactics, 191 groups, 914 software across Enterprise + ICS + Mobile.

### Step 2: Restore local scripts (run sequentially)

```bash
export DATABASE_URL="postgresql://..."

# ETDA actors (~30s)
node scripts/sync-thaicert.mjs

# NIST 800-53, MITRE Engage, RE&CT (~60s)
node scripts/sync-frameworks.mjs
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

### Step 4: Wait for scheduled enrichment

These run automatically via Vercel cron and don't need manual triggering:

- **NVD enrichment** (every 4h) — adds CVSS scores to CVEs, 20 per batch
- **VT enrichment** (every 8h) — adds VirusTotal verdicts to IOCs, 10 per batch
- **OTX** (every 12h) — catches up with more pulses each run

### Step 5: Trigger GitHub Actions

Using gh CLI at `/Users/peripan/dev/gh_CLI/bin/gh`:

```bash
GH=/Users/peripan/dev/gh_CLI/bin/gh
REPO=PerIPan/mitre-explorer-plus

# Sigma rules (~3000 rules, takes ~2-3 min)
$GH workflow run sync-sigma.yml --repo $REPO

# Atomic Red Team tests (~1500 tests, takes ~2-3 min)
$GH workflow run sync-atomic.yml --repo $REPO

# Check status
$GH run list --repo $REPO --limit 5
```

Or via browser: `https://github.com/PerIPan/mitre-explorer-plus/actions` → select workflow → "Run workflow"

### Step 6: Verify counts

```sql
SELECT 'techniques' as tbl, COUNT(*) FROM techniques
UNION ALL SELECT 'tactics', COUNT(*) FROM tactics
UNION ALL SELECT 'threat_groups', COUNT(*) FROM threat_groups
UNION ALL SELECT 'threat_reports', COUNT(*) FROM threat_reports
UNION ALL SELECT 'ioc_entries', COUNT(*) FROM ioc_entries
UNION ALL SELECT 'cve_details', COUNT(*) FROM cve_details
UNION ALL SELECT 'sigma_rules', COUNT(*) FROM sigma_rules
UNION ALL SELECT 'atomic_tests', COUNT(*) FROM atomic_tests
UNION ALL SELECT 'nist_controls', COUNT(*) FROM nist_controls
UNION ALL SELECT 'engage_mappings', COUNT(*) FROM engage_mappings
UNION ALL SELECT 'react_actions', COUNT(*) FROM react_actions
UNION ALL SELECT 'external_actors', COUNT(*) FROM external_actors
UNION ALL SELECT 'defensive_mappings', COUNT(*) FROM defensive_mappings
ORDER BY tbl;
```

Expected totals after full restoration:

| Table | Expected |
|-------|----------|
| techniques | ~1,094 |
| tactics | 40 |
| threat_groups | ~191 |
| threat_reports | ~60+ |
| ioc_entries | ~2,500+ |
| cve_details | ~1,589 |
| sigma_rules | ~3,000 |
| atomic_tests | ~1,500 |
| nist_controls | ~5,300 |
| engage_mappings | ~1,100 |
| react_actions | ~216 |
| external_actors | 514 |
| defensive_mappings | ~800 |

### Notes

- OTX is the slowest feed — batches of 3 pulses per run, needs multiple triggers to catch up
- Sigma and Atomic require GitHub Actions (not Vercel cron)
- NVD enrichment without API key uses 6s delay between requests — very slow for large batches
- The `CRON_SECRET` is in Vercel env vars (encrypted). Pull with: `npx vercel env pull`
