<p align="center">
  <img src="public/diamond-favicon.svg" width="64" height="64" alt="MITRE Explorer Plus" />
</p>

<h1 align="center">MITRE Explorer Plus</h1>

<p align="center">
  Multi-domain threat intelligence platform built on <strong>MITRE ATT&CK v19</strong>, <strong>ATLAS</strong>, and <strong>25+ interconnected data sources</strong>.<br/>
  One interface for adversary behaviour, detection, vulnerability management, compliance, and application security.
</p>

<p align="center">
  <a href="https://mitre-explorer.org">mitre-explorer.org</a> &nbsp;|&nbsp;
  <a href="https://mitre-explorer.org/api/mcp">MCP endpoint</a> &nbsp;|&nbsp;
  <a href="https://mitre-explorer.org/.well-known/agent-card.json">A2A Agent Card</a> &nbsp;|&nbsp;
  <a href="https://mitre-explorer.org/.well-known/security.txt">security.txt</a> &nbsp;|&nbsp;
  <a href="https://www.virustotal.com/gui/domain/mitre-explorer.org">VirusTotal 0/94</a>
</p>

---

## What it does

| Capability | Details |
|------------|---------|
| **Multi-domain ATT&CK + ATLAS** | Enterprise, ICS, Mobile and ATLAS (AI/ML) with a domain switcher and a cross-domain "All" view |
| **360° entity views** | Search any entity, then explore it through a dedicated map: Technique, Threat Actor, Malware, Application, Sector, Tactic, Mitigation, Data Source, OWASP, ICS Asset, or a D3 force graph |
| **ATT&CK matrix** | Heatmap with sub-technique counts, actor-comparison overlay (up to 3 groups), HTML export with filters |
| **Applications** | 19,700 vendor/product pairs linked to CVEs through CWE → CAPEC → ATT&CK → threat groups |
| **CVEs** | 107,000 vulnerabilities from CVElistV5 with NVD enrichment, CISA KEV flags and EPSS exploit probability, each carrying technique IDs and affected apps |
| **Advisories** | 35,700 GitHub Security Advisories plus an OSV corpus covering Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz and Chainguard |
| **Ecosystems** | Per-ecosystem dashboards across 40+ registries and distros: severity breakdown, top packages, advisory feed |
| **IOCs** | 154,000 indicators (IPs, domains, hashes, URLs) from OTX, ThreatFox and MalwareBazaar, enriched with VirusTotal verdicts |
| **Detection** | 3,146 Sigma rules, 2,042 Atomic Red Team tests, ATT&CK v19 detection strategies and analytics |
| **Defence** | 5,750 D3FEND mappings across 153 countermeasures, browsable by defensive tactic, covering Enterprise **and ICS** |
| **Compliance** | 224 frameworks bridged to ATT&CK through the Secure Controls Framework: 1,534 controls and 58,600 cross-references spanning NIS2, DORA, GDPR, EU CRA, EU AI Act, HIPAA, PCI DSS, SOC 2, CMMC, FedRAMP and more |
| **ICS and OT** | 18 ATT&CK for ICS assets with curated Purdue-model placement (level, zone, boundary), the techniques that target them, and the D3FEND countermeasures that defend them |
| **Threat actors** | 180 ATT&CK groups plus 514 ThaiCERT/ETDA external actors with country, motivation and state-sponsor attribution |
| **Sector intelligence** | 12 industry verticals with their threat landscape: groups, techniques, campaigns, CVEs, vulnerable apps |
| **MCP + A2A** | An **MCP server** (`/api/mcp`) and an **A2A agent** over the same 43-tool catalogue, so Claude, Cursor or any agent can query all of the above directly — anonymous, no key. See [For AI agents](#for-ai-agents) |

## For AI agents

Two protocols front the same tool catalogue. Both are anonymous and need no key.

### MCP (Model Context Protocol)

```
https://mitre-explorer.org/api/mcp
```

Streamable HTTP, stateless, 43 tools. Add it to any MCP client:

```json
{ "mcpServers": { "mitre-explorer": { "url": "https://mitre-explorer.org/api/mcp" } } }
```

The server ships `instructions` and a `mitre://guide` resource covering tool selection, pagination, data provenance and the vocabularies each filter accepts, so a model does not have to guess. JSON-RPC batches are capped at 100 members with a concurrency gate, which removes the amplification a stateless endpoint would otherwise hand an anonymous caller.

### A2A (Agent-to-Agent)

25 skills over JSON-RPC 2.0, described by the [Agent Card](https://mitre-explorer.org/.well-known/agent-card.json), powered by Gemini with multi-round tool chaining. Rate limited to 50 requests per day per IP, bypassed with `Authorization: Bearer <A2A_API_KEY>`.

The difference: MCP gives a client the raw tools to orchestrate itself; A2A answers a question in prose and returns a structured artifact alongside it.

## Architecture

```
Next.js 16 App Router (React 19 + TypeScript + Tailwind 4)
     |
     +-- app/api  — v1 REST, MCP, A2A, 11 Vercel crons
     |        |
     |        +-- PostgreSQL on Neon (80 tables + 3 matviews)
     |        |
     |        +-- Gemini (A2A agent, 25 skills)
     |
     +-- 11 GitHub Actions workflows (ingests that overflow Vercel's 300s cron cap)
```

## Data sources

| Source | What | Scale | Update |
|--------|------|------:|--------|
| MITRE ATT&CK STIX | Techniques, groups, campaigns, software, mitigations, tactics, ICS assets | v19.2 | GH Actions |
| MITRE ATLAS | AI/ML techniques, mitigations, cross-references | 155 techniques | Seed |
| CVElistV5 | CVE metadata, CWEs, affected products (CPE) | 107,295 | Seed + delta |
| NVD API | CVSS scores, descriptions, CPE enrichment | hourly | GH Actions |
| CISA KEV | Known exploited vulnerabilities | 1,716 | Cron |
| EPSS (FIRST.org) | Daily exploit-probability scoring | per CVE | Cron |
| GitHub Security Advisories | OSS advisories across npm, PyPI, Maven, Go, RubyGems, … | 35,736 | GH Actions |
| OSV.dev | Non-GHSA ecosystems: Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, Chainguard | 1.9M | GH Actions |
| CAPEC STIX | CWE → CAPEC → ATT&CK bridge plus the 615-pattern taxonomy | 1,483 mappings | Seed |
| CTID | Hand-curated CVE → technique mappings | 198 | Seed |
| AlienVault OTX | Threat reports and IOC indicators | ongoing | Cron |
| ThreatFox + MalwareBazaar | Malware IOCs with family attribution | 154,756 IOCs | Cron |
| SigmaHQ | Detection rules per technique | 3,146 | GH Actions |
| Atomic Red Team | Adversary-emulation tests | 2,042 | GH Actions |
| MITRE D3FEND | Defensive countermeasures, Enterprise + ICS | 5,750 mappings | Cron (weekly) |
| Secure Controls Framework | Regulatory frameworks bridged to ATT&CK | 224 frameworks, 58,631 refs | GH Actions |
| NIST CSF v2 | Subcategories plus the CRI Profile crosswalk to ATT&CK | 132 subcategories | Cron |
| NIST SP 800-53 / 800-171 | Control catalogues, titles from NIST CPRT | 5,264 controls | Seed |
| ThaiCERT/ETDA | External threat-actor profiles | 514 | Seed |
| OWASP Top 10 | Web (2021), ML (2023), LLM (2025) via CWE + ATLAS | 30 categories | Seed |
| MITRE Engage, RE&CT, VERIS | Deception, response, incident classification | 2,400+ | Seed |
| Azure + GCP | Cloud security controls | 1,450+ | Seed |
| RSS feeds | DFIR Report, Unit42, Microsoft Security, Talos | ongoing | Cron |
| VirusTotal | IOC verdict enrichment and a domain self-scan | ongoing | Cron |

## Frameworks

Each has a dedicated page under `/frameworks`, mapped to ATT&CK techniques:

OWASP Top 10 (web / ML / LLM) · NIST CSF v2 · NIST 800-53 · ISO/IEC 27001:2022 · **MITRE D3FEND** · MITRE Engage · RE&CT · VERIS · CAPEC · Cloud controls (Azure, GCP) · Purdue model · Detection strategies · Atomic tests · EU CRA *(reference)* · OWASP AI Exchange *(reference)*

`/compliance` covers the 224 SCF-bridged regulatory frameworks separately, since those reach ATT&CK through control cross-references rather than direct technique mappings.

## CVE → technique paths

Three independent paths link CVEs to ATT&CK techniques, and the UI distinguishes them because their confidence differs:

```
Path 1: CAPEC bridge (inferred, broad coverage)
  CVE → cve_weaknesses → capec_mappings → techniques

Path 2: IOC path
  CVE → ioc_entries → technique_iocs → techniques

Path 3: CTID direct (curated, high confidence, 198 CVEs)
  CVE → synthetic CWE → CTID capec entry → techniques
```

Inferred links are never presented as confirmed attribution.

## Tech stack

| Layer | Tech |
|-------|------|
| Framework | Next.js 16 (App Router, RSC, server actions) |
| Frontend | React 19, TypeScript, Tailwind CSS 4 |
| Visualisation | D3.js (force graph), Recharts |
| Search | Fuse.js (fuzzy, client-side) |
| State | TanStack Query v5, React Context |
| Backend | Next.js route handlers on Vercel (serverless) |
| Database | PostgreSQL on Neon (80 tables, matviews for hot joins) |
| Agents | MCP (`mcp-handler`) and A2A (Google Gemini tool-calling) |
| Validation | Zod |
| Security | DOMPurify, CSP headers, rate limiting, approximate-count endpoints |
| Dependencies | Renovate, grouped and scheduled |

## Ingest jobs

**Vercel cron** (lightweight, under the 300s cap):

| Job | Schedule | What |
|-----|----------|------|
| `ingest-cisa-kev` | Daily | CISA Known Exploited Vulnerabilities |
| `ingest-abuse-ch` | Daily | ThreatFox + MalwareBazaar IOCs |
| `ingest-otx` | Every 6h | AlienVault OTX pulses and IOCs |
| `ingest-rss` | Daily | DFIR Report, Unit42, Microsoft, Talos |
| `enrich-nvd` | Every 4h | CVSS enrichment for IOC CVEs |
| `enrich-vt` | 3×/day | VirusTotal verdict enrichment |
| `sync-d3fend` | Weekly | D3FEND countermeasures, Enterprise + ICS |
| `sync-csf` | Weekly | NIST CSF v2 subcategories + CRI Profile |
| `sync-epss` | Daily | FIRST.org exploit-probability scoring |
| `refresh-matviews` | 2×/day | `app_technique_groups`, `package_summary` |
| `scan-site-health` | Weekly | VirusTotal domain self-scan |

**GitHub Actions** (heavy ingests that overflow the cron cap):

| Workflow | Schedule | What |
|----------|----------|------|
| `update-attack` | Scheduled + manual | ATT&CK STIX refresh across all domains |
| `sync-osv` | Daily delta, monthly full | OSV advisories across 30+ non-GHSA ecosystems |
| `sync-ghsa` / `sync-ghsa-delta` | Monthly / daily | GitHub Security Advisories corpus |
| `sync-cve-delta` | Daily | NVD API new and modified CVEs |
| `sync-cve-products` | Hourly | Re-fetch NVD CPE for CVEs missing product links |
| `sync-scf` | Twice yearly + manual | Secure Controls Framework workbook ingest |
| `sync-sigma` | Weekly | SigmaHQ rule pack |
| `sync-atomic` | Weekly | Atomic Red Team tests |
| `refresh-cti-heat` | Scheduled | Technique heat signals |
| `checks` | On push | Threshold consistency gate |

## Quick start

```bash
npm install

npm run dev        # Next.js on :3000
npm run typecheck  # tsc --noEmit
npm test           # node --test, parser and ingest-guard unit tests
npm run build

# seed from CVElistV5, ATT&CK, ATLAS and the reference datasets
DATABASE_URL=postgresql://postgres@localhost:5432/mitre npm run seed
```

### Environment variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (Neon or local) |
| `GEMINI_API_KEY` | Google Gemini API key (A2A) |
| `VT_API_KEY` | VirusTotal API key (IOC enrichment) |
| `NVD_API_KEY` | NVD API key, lifts the rate limit from 5 to 50 requests per 30s |
| `CRON_SECRET` | Auth token for cron endpoints |
| `A2A_API_KEY` | Optional bearer key bypassing the A2A daily limit (unset = no bypass) |

## Codebase

~56,500 lines across `app/`, `src/` and `scripts/`.

```
app/                     Next.js App Router — pages and API routes
app/api/v1/              31 REST endpoint groups
app/api/mcp/             MCP server (Streamable HTTP, 43 tools)
app/api/a2a/             A2A agent endpoint (Gemini tool-calling)
app/api/cron/            14 cron handlers, 11 on a Vercel schedule
src/views/               57 top-level page components
src/components/          Layout, charts, 360 map views, shared primitives
src/hooks/               TanStack Query hooks, URL-param helpers
src/lib/tools/           Shared tool catalogue behind both MCP and A2A
scripts/                 Heavy ingesters run from GitHub Actions
seed/                    Schema, migrations, Python seeders
.github/workflows/       11 scheduled workflows
```

## Security

Vulnerability reports go through [GitHub private vulnerability reporting](https://github.com/PerIPan/explorer-plus/security/advisories/new); see [security.txt](https://mitre-explorer.org/.well-known/security.txt).

## License

ISC

---

*Not affiliated with or endorsed by MITRE Corporation. ATT&CK®, ATLAS™, D3FEND™, CAPEC™ and Engage™ are trademarks of The MITRE Corporation.*
*contact @ mitre-explorer.org*
