<p align="center">
  <img src="public/diamond-favicon.svg" width="64" height="64" alt="MITRE Explorer Plus" />
</p>

<h1 align="center">MITRE Explorer Plus</h1>

<p align="center">
  Multi-domain threat intelligence platform on <strong>MITRE ATT&CK</strong>, <strong>ATLAS</strong>, and <strong>25+ interconnected data sources</strong>.<br/>
  One interface for adversary behaviour, detection, vulnerability management, compliance, and application security.
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
| **360° Entity Views** | Search any entity — explore via Technique Map, Actor Profile, Software Map, Application Map, Sector Map, Diamond Entities force graph |
| **ATT&CK Matrix** | Heatmap with sub-technique counts, actor-comparison overlay (up to 3 groups), HTML export with filters |
| **Applications** | 11K+ vendor/products linked to CVEs via CWE → CAPEC → ATT&CK techniques → threat groups |
| **CVEs** | 26K+ vulnerabilities from CVElistV5 + NVD enrichment + CISA KEV + EPSS exploit probability, with technique IDs and affected apps |
| **Advisories** | Unified GHSA + OSV list — 8K+ GitHub Security Advisories across npm/PyPI/Maven/Go/… and 50K+ OSV advisories covering Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, Chainguard |
| **Ecosystems** | Per-ecosystem dashboards for 40+ OSS registries, OS distros, and container distros — severity breakdown, top packages, advisory feed |
| **IOCs** | 5,800+ indicators (IPs, domains, hashes, URLs) from OTX, ThreatFox, MalwareBazaar, enriched with VirusTotal verdicts |
| **Detection** | 3,100+ Sigma rules, 1,770+ Atomic Red Team tests, 5,000+ D3FEND countermeasures, ATT&CK v18 detection strategies + analytics |
| **Frameworks** | OWASP Top 10 (Web 2021, ML 2023, LLM 2025), NIST CSF v2, NIST 800-53, CAPEC (615 patterns), MITRE Engage, RE&CT, VERIS, Azure + GCP cloud controls, EU CRA (wip), OWASP AI Exchange (wip) |
| **Threat actors** | 191 ATT&CK groups + 514 ThaiCERT/ETDA external actors with country, motivation, state-sponsor attribution |
| **Sector intelligence** | 12 industry verticals with threat landscape — groups, techniques, campaigns, CVEs, vulnerable apps |
| **A2A Agent Protocol v1.0** | 24 skills — AI agents query this knowledge base via JSON-RPC 2.0, powered by Gemini |

## Architecture

```
Next.js 15 App Router (React 19 + TypeScript + Tailwind 4)
     |
     +-- API routes under app/api (v1 REST + A2A + 11 Vercel crons)
     |        |
     |        +-- PostgreSQL on Neon (~40 tables + matviews)
     |        |
     |        +-- A2A endpoint (Gemini 3.1 Flash-Lite, 24 skills)
     |
     +-- 6 GitHub Actions workflows (heavy ingest jobs outside Vercel's 300s cron cap)
```

## Data sources

| Source | What | Rows | Update |
|--------|------|-----:|--------|
| MITRE ATT&CK STIX | Techniques, groups, campaigns, software, mitigations, tactics | 22K+ | Seed |
| MITRE ATLAS | AI/ML techniques, mitigations, cross-references | 200+ | Seed |
| CVElistV5 | CVE metadata, CWEs, affected products (CPE) | 26K+ CVEs | Seed |
| NVD API | CVSS scores, descriptions, CPE enrichment | hourly | GH Actions |
| CISA KEV | Known exploited vulnerabilities | 1,550+ | Cron |
| EPSS (FIRST.org) | Daily exploit-probability scoring | per CVE | Cron |
| GitHub Security Advisories | OSS advisories across npm, PyPI, Maven, Go, RubyGems, … | 8K+ | GH Actions |
| OSV.dev | Non-GHSA ecosystems — Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, Chainguard, … | 50K+ | GH Actions |
| CAPEC STIX | CWE → CAPEC → ATT&CK technique bridge + 615-pattern taxonomy | 1,480+ | Seed |
| CTID | Hand-curated CVE → technique mappings | 198 | Seed |
| AlienVault OTX | Threat reports + IOC indicators | 80+ reports | Cron |
| ThreatFox + MalwareBazaar | Malware IOCs with family attribution | 5,800+ | Cron |
| SigmaHQ | Detection rules per technique | 3,100+ | GH Actions |
| Atomic Red Team | Adversary-emulation tests | 1,770+ | GH Actions |
| D3FEND | Defensive countermeasures | 5,000+ | Cron |
| NIST CSF v2 | Cybersecurity Framework v2 subcategories + CRI Profile crosswalk to ATT&CK | 300+ | Cron |
| NIST 800-53 | Compliance controls | 5,260+ | Seed |
| ThaiCERT/ETDA | External threat-actor profiles | 514 | Seed |
| OWASP Top 10 | Web (2021), ML (2023), LLM (2025) via CWE + ATLAS | 30 | Seed |
| MITRE Engage, RE&CT, VERIS | Deception, response, incident classification | 2,400+ | Seed |
| Azure + GCP | Cloud security controls | 1,450+ | Seed |
| RSS feeds | DFIR Report, Unit42, Microsoft Security, Talos | 80+ reports | Cron |
| VirusTotal | IOC verdict enrichment + site-health scan | ongoing | Cron |

## CVE → technique paths

Three independent paths link CVEs to ATT&CK techniques:

```
Path 1: CAPEC bridge (~20K CVEs)
  CVE → cve_weaknesses → capec_mappings → techniques

Path 2: IOC path (~500 CVEs)
  CVE → ioc_entries → technique_iocs → techniques

Path 3: CTID direct (198 CVEs)
  CVE → synthetic CWE → CTID capec entry → techniques
```

Full documentation: [docs/technique_glue.md](docs/technique_glue.md)

## Tech stack

| Layer | Tech |
|-------|------|
| Framework | Next.js 15 (App Router, RSC, server actions) |
| Frontend | React 19, TypeScript, Tailwind CSS 4 |
| Visualisation | D3.js (force graph), Recharts |
| Search | Fuse.js (fuzzy client-side) |
| State | TanStack Query v5, React Context |
| Backend | Next.js route handlers on Vercel (serverless) |
| Database | PostgreSQL on Neon (~40 tables, matviews for hot joins) |
| AI | Google Gemini 3.1 Flash-Lite (A2A agent) |
| Validation | Zod |
| Security | DOMPurify, CSP headers, rate limiting, approximate-count endpoints |

## Ingest jobs

**Vercel cron** (lightweight, <300 s runs):

| Job | Schedule | What |
|-----|----------|------|
| `ingest-cve-delta` | Daily 04:00 | NVD API new/modified CVEs |
| `ingest-cisa-kev` | Daily 03:00 | CISA Known Exploited Vulnerabilities |
| `ingest-abuse-ch` | Daily 02:00 | ThreatFox + MalwareBazaar IOCs |
| `ingest-otx` | Every 3 h | AlienVault OTX pulses + IOCs |
| `ingest-rss` | Every 6 h | DFIR Report, Unit42, Microsoft, Talos |
| `enrich-nvd` | Every 4 h | CVSS enrichment for IOC CVEs |
| `enrich-vt` | Every 8 h | VirusTotal verdict enrichment |
| `sync-d3fend` | Monthly | D3FEND countermeasures |
| `sync-csf` | Weekly | NIST CSF v2 subcategories + CRI Profile |
| `sync-epss` | Daily 03:10 | FIRST.org exploit-probability scoring |
| `refresh-matviews` | Every 8 h | `app_technique_groups`, `package_summary` |
| `scan-site-health` | Weekly | VirusTotal domain self-scan |

**GitHub Actions** (heavy ingests that overflow Vercel's 300 s cap):

| Workflow | Schedule | What |
|----------|----------|------|
| `sync-osv` | Daily delta 05:30 UTC · Monthly full 1st 04:00 UTC | OSV advisories across 30+ non-GHSA ecosystems |
| `sync-cve-products` | Hourly `:17` | Re-fetch NVD CPE for CVEs missing product links |
| `sync-ghsa` | Monthly | Full GitHub Security Advisories corpus |
| `sync-ghsa-delta` | Daily | GHSA incremental updates |
| `sync-sigma` | Weekly | SigmaHQ rule pack refresh |
| `sync-atomic` | Weekly | Atomic Red Team test refresh |

## A2A Agent Protocol

AI agents can query this knowledge base programmatically via the [Agent Card](https://mitre-explorer.org/.well-known/agent-card.json).

- **Protocol**: A2A v1.0 JSON-RPC 2.0 over HTTPS
- **24 skills**: CVEs, techniques, groups, software, campaigns, mitigations, IOCs, Sigma rules, Atomic tests, sectors, applications, GHSA/OSV advisories, packages, CAPEC patterns, OWASP Top 10, external actors
- **Dual artifacts**: Human-readable summary + structured JSON data
- **Multi-round**: Agentic tool chaining (search → profile, up to 3 rounds)
- **Rate limit**: 50 req / day / IP, no auth required

Example: *"ask mitre-explorer.org, using the A2A Google GenAI protocol, which Applications have been affected by new CVEs published in the previous week — show me the relevant techniques and any known OSV advisories on the same packages."*

## Quick start

```bash
npm install

# local dev server (Next.js on :3000)
npm run dev

# typecheck
npm run typecheck

# seed database from CVElistV5, ATT&CK, ATLAS, and reference datasets
DATABASE_URL=postgresql://postgres@localhost:5432/mitre npm run seed
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (Neon or local) |
| `GEMINI_API_KEY` | Google Gemini API key (A2A) |
| `VT_API_KEY` | VirusTotal API key (IOC enrichment) |
| `NVD_API_KEY` | NVD API key — lifts rate limit from 5 to 50 req / 30 s |
| `CRON_SECRET` | Auth token for cron endpoints |

## Codebase

~42K lines of custom code across app/, src/, and scripts/.

```
app/                     Next.js 15 App Router — pages + API routes
src/views/               Top-level page components (Dashboard, CVEs, Advisories, Ecosystems, …)
src/components/          Layout, charts, maps, shared primitives
src/hooks/               TanStack Query hooks (useApi.ts), URL-param helpers
src/lib/                 Client helpers — API fetch, types, ecosystems registry
app/api/v1/              29 REST endpoint groups
app/api/a2a/             A2A agent endpoint (Gemini tool-calling)
app/api/cron/            11 Vercel cron handlers
scripts/                 Heavy ingesters run from GitHub Actions
.github/workflows/       6 scheduled ingest workflows
```

## License

ISC

---

*Not affiliated with or endorsed by MITRE Corporation.*
*contact @ mitre-explorer.org*
