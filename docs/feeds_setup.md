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
