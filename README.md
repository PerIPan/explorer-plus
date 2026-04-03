<p align="center">
  <img src="public/diamond-favicon.svg" width="64" height="64" alt="MITRE Explorer Plus" />
</p>

<h1 align="center">MITRE Explorer Plus</h1>

<p align="center">
  Multi-domain threat intelligence platform on <strong>MITRE ATT&CK</strong>, <strong>ATLAS</strong>, and <strong>20+ interconnected data sources</strong>.<br/>
  One interface for adversary behavior, detection, compliance, and application security.
</p>

<p align="center">
  <a href="https://mitre-explorer.org">mitre-explorer.org</a> &nbsp;|&nbsp;
  <a href="https://mitre-explorer.org/.well-known/agent-card.json">A2A Agent Card</a> &nbsp;|&nbsp;
  <a href="https://www.virustotal.com/gui/domain/mitre-explorer.org">VirusTotal 0/94</a>
</p>

---

## What it does

| Capability | Details |
|------------|---------|
| **Multi-domain ATT&CK + ATLAS** | Enterprise, ICS, Mobile, ATLAS (AI/ML threats) with domain switcher and cross-domain "All" view |
| **360 Views** | Search any entity — explore via Technique Map, Actor Profile, Software Map, Application Map, Sector Map, or D3 force graph |
| **ATT&CK Matrix** | Heatmap with sub-technique counts, actor comparison overlay (up to 3 groups), HTML export with filters |
| **Applications** | 11K+ vendor/products linked to CVEs via CWE → CAPEC → ATT&CK techniques → threat groups |
| **CVEs** | 21K+ vulnerabilities from CVElistV5 + NVD enrichment + CISA KEV, with technique IDs and affected apps |
| **IOCs** | 5,800+ indicators (IPs, domains, hashes, URLs) from OTX, ThreatFox, MalwareBazaar, enriched with VirusTotal verdicts |
| **Detection** | 3,100+ Sigma rules, 1,770+ Atomic Red Team tests, 5,000+ D3FEND countermeasures, detection strategies + analytics |
| **Frameworks** | NIST 800-53, MITRE Engage, RE&CT, VERIS, Azure + GCP cloud controls — all mapped per technique |
| **Threat actors** | 191 ATT&CK groups + 514 ThaiCERT/ETDA external actors with country, motivation, state sponsor attribution |
| **Sector intelligence** | 12 industry verticals with threat landscape — groups, techniques, campaigns, CVEs, vulnerable apps |
| **A2A Agent Protocol v1.0** | 26 tools, 16 skills — AI agents query this knowledge base via JSON-RPC 2.0, powered by Gemini |

## Architecture

```
React SPA (Vite + TypeScript + Tailwind)
     |
     +-- Vercel Serverless API (40+ endpoints)
     |        |
     |        +-- PostgreSQL on Neon (44 tables + 1 materialized view)
     |        |
     |        +-- A2A endpoint (Gemini 3.1 Flash-Lite, 26 function tools)
     |
     +-- 9 automated cron jobs (daily feeds)
```

## Data sources

| Source | What | Rows | Update |
|--------|------|-----:|--------|
| MITRE ATT&CK STIX | Techniques, groups, campaigns, software, mitigations, tactics | 22K+ | Seed |
| MITRE ATLAS | AI/ML techniques, mitigations, cross-references | 200+ | Seed |
| CVElistV5 | CVE metadata, CWEs, affected products | 21K CVEs | Seed |
| NVD API | CVSS scores, descriptions, CPE enrichment | daily delta | Cron |
| CISA KEV | Known exploited vulnerabilities | 1,556 | Cron |
| CAPEC STIX | CWE to CAPEC to ATT&CK technique bridge | 1,483 | Seed |
| CTID | Hand-curated CVE to technique mappings | 198 | Seed |
| AlienVault OTX | Threat reports + IOC indicators | 80+ reports | Cron |
| ThreatFox + MalwareBazaar | Malware IOCs with family attribution | 5,800+ | Cron |
| SigmaHQ | Detection rules per technique | 3,105 | Seed |
| Atomic Red Team | Adversary emulation tests | 1,773 | Seed |
| D3FEND | Defensive countermeasures | 5,036 | Cron |
| NIST 800-53 | Compliance controls | 5,264 | Seed |
| ThaiCERT/ETDA | External threat actor profiles | 514 | Seed |
| MITRE Engage, RE&CT, VERIS | Deception, response, incident classification | 2,400+ | Seed |
| Azure + GCP | Cloud security controls | 1,454 | Seed |
| RSS feeds | DFIR Report, Unit42, Microsoft Security, Talos | 80+ reports | Cron |
| VirusTotal | IOC verdict enrichment + site health scan | ongoing | Cron |

## CVE to technique paths

Three independent paths link CVEs to ATT&CK techniques:

```
Path 1: CAPEC bridge (20K CVEs)
  CVE -> cve_weaknesses -> capec_mappings -> techniques

Path 2: IOC path (489 CVEs)
  CVE -> ioc_entries -> technique_iocs -> techniques

Path 3: CTID direct (198 CVEs)
  CVE -> synthetic CWE -> CTID capec entry -> techniques
```

Full documentation: [docs/technique_glue.md](docs/technique_glue.md)

## Tech stack

| Layer | Tech |
|-------|------|
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4 |
| Visualization | D3.js (force graph), Recharts (charts) |
| Search | Fuse.js (fuzzy client-side) |
| State | React Query, React Context |
| Backend | Vercel serverless functions (TypeScript) |
| Database | PostgreSQL on Neon (44 tables, 1.4M-row materialized view) |
| AI | Google Gemini 3.1 Flash-Lite (A2A agent) |
| Validation | Zod |
| Security | DOMPurify, CSP headers, rate limiting |

## Cron jobs

| Job | Schedule | What |
|-----|----------|------|
| `ingest-cve-delta` | Daily 04:00 | NVD API new/modified CVEs (200/run) |
| `ingest-cisa-kev` | Daily 03:00 | CISA Known Exploited Vulnerabilities |
| `ingest-abuse-ch` | Daily 02:00 | ThreatFox + MalwareBazaar IOCs |
| `ingest-otx` | Every 3h | AlienVault OTX pulses + IOCs |
| `ingest-rss` | Every 6h | DFIR Report, Unit42, Microsoft, Talos |
| `enrich-nvd` | Every 4h | CVSS enrichment for IOC CVEs |
| `enrich-vt` | Every 8h | VirusTotal verdict enrichment |
| `sync-d3fend` | Monthly | D3FEND countermeasures (15 techniques/run) |
| `scan-site-health` | Daily 12:00 | VirusTotal domain self-scan |

## A2A Agent Protocol

AI agents can query this knowledge base programmatically via the [Agent Card](https://mitre-explorer.org/.well-known/agent-card.json).

- **Protocol**: A2A v1.0 JSON-RPC 2.0 over HTTPS
- **26 tools**: CVEs, techniques, groups, software, campaigns, mitigations, IOCs, Sigma rules, Atomic tests, sectors, applications, frameworks, reports, external actors
- **Dual artifacts**: Human-readable summary + structured JSON data
- **Multi-round**: Agentic tool chaining (search then profile, up to 3 rounds)
- **Rate limit**: 50 req/day per IP, no auth required

Example: *"ask mitre-explorer.org, using the A2A Google GenAI protocol, which Applications have been affected by new CVEs published in the previous week, show me the relevant Techniques"*

## Quick start

```bash
npm install

# seed local database
DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack npm run seed

# start dev
npm run dev:frontend  # Vite on :5173
npm run dev:api       # API on :3001
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `GEMINI_API_KEY` | Google Gemini API key (A2A) |
| `VT_API_KEY` | VirusTotal API key (IOC enrichment) |
| `CRON_SECRET` | Auth token for cron endpoints |

## Codebase

**24,764 lines** of custom code across **167 files**.

```
src/pages/           7,793 lines   28 route components
src/components/      6,139 lines   layout, charts, maps, shared
api/v1/              4,932 lines   40+ REST endpoints
api/cron/            1,567 lines   9 automated jobs
api/a2a/               458 lines   A2A agent endpoint
scripts/             2,109 lines   bulk ingestion scripts
```

## License

ISC

---

*Not affiliated with or endorsed by MITRE Corporation.*
*contact @ mitre-explorer.org*
