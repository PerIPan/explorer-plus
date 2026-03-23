# ATT&CK Explorer Plus

A threat intelligence platform built on **MITRE ATT&CK**. One interface for adversary behavior, detection, and compliance.

## Features

- **14 data sources** — techniques, groups, campaigns, software, mitigations, data sources, tactics, sectors + live feeds from AlienVault OTX, RSS, CISA KEV, Sigma, Atomic Red Team, D3FEND
- **Relationships Explorer** — search any entity, see connections via Threat Actor Profile, Technique Map, or D3 force graph
- **ATT&CK Matrix** — heatmap showing technique coverage across kill chain tactics
- **Frameworks** — NIST 800-53 controls, MITRE Engage deception, RE&CT response playbooks mapped per technique
- **IOCs** — CVEs, hashes, domains, IPs linked to AlienVault OTX indicator pages
- **Non-MITRE Actors** — 500+ threat actors from ThaiCERT/ETDA with motivation, state sponsor, and victim data
- **Global sector filter** — narrow the entire view by industry (Finance, Healthcare, etc.)
- **Light/Dark theme** — toggle between themes, respects system preference
- **Auto-updating** — scheduled feeds keep data current; ATT&CK re-seeded on new MITRE releases

## Tech Stack

| Layer | Tech |
|-------|------|
| Frontend | React 19, TypeScript, Vite, Tailwind CSS 4 |
| Visualization | D3.js (force graph), Recharts (charts) |
| Search | Fuse.js (fuzzy client-side search) |
| State | React Query (server state), React Context (theme, sector filter) |
| Backend | Express.js + Vercel serverless functions |
| Database | PostgreSQL (@vercel/postgres) |
| Validation | Zod |
| Security | DOMPurify (XSS prevention) |

## Quick Start

### Prerequisites

- Node.js 18+
- PostgreSQL (local or remote)
- Python 3.10+ (for seeding ATT&CK data)

### Setup

```bash
# install dependencies
npm install

# create python venv for seed scripts
python3 -m venv venv
./venv/bin/pip install mitreattack-python psycopg2-binary

# seed the database (local)
DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack npm run seed

# start dev servers (API + frontend)
npm run dev:api   # API on port 3001
npm run dev:frontend  # Vite on port 5173
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string (local dev) |
| `POSTGRES_URL` | Vercel Postgres connection string (production) |

## Project Structure

```
src/
  pages/           # 28 route components (lazy-loaded)
  components/
    layout/         # Sidebar, SearchBar, SectorDropdown
    graph/          # D3 force-directed graph
    matrix/         # ATT&CK matrix heatmap
    charts/         # Recharts (campaigns, tactics, sectors)
    relationships/  # Actor profile, technique map, data model
    shared/         # Badge, DataTable, Pagination, EntityLink
  contexts/         # ThemeContext, SectorContext
  hooks/            # useApi, useFuseFilter, useThemeColors
  lib/              # API client, types, sanitize

api/v1/             # Vercel serverless API endpoints
server/             # Local Express dev server
seed/               # Python scripts to seed ATT&CK data
```

## Deployment

Deployed on **Vercel** with:
- Vite frontend build (`npm run build:frontend`)
- Serverless API functions in `api/v1/`
- Vercel Postgres for the database

## Data Sources

| Source | Type | Update |
|--------|------|--------|
| MITRE ATT&CK | Techniques, groups, campaigns, software, mitigations, tactics | Manual seed |
| AlienVault OTX | Threat reports, IOCs | Scheduled |
| CISA KEV | Known exploited vulnerabilities | Scheduled |
| SigmaHQ | Detection rules | Scheduled |
| Atomic Red Team | Test procedures | Seed |
| MITRE D3FEND | Defensive countermeasures | Seed |
| ThaiCERT/ETDA | Extended threat actors (500+) | Seed |
| MITRE Engage | Adversary engagement activities | Seed |
| RE&CT | Incident response actions | Seed |
| NIST 800-53 | Security controls | Seed |

## Scripts

```bash
npm run dev:frontend    # Vite dev server
npm run dev:api         # Express API server
npm run build:frontend  # Production build
npm run typecheck       # TypeScript type check
npm run seed            # Seed local database
npm run seed:prod       # Seed production database
npm run seed:update     # Update feeds only
npm run seed:verify     # Verify seed integrity
```

## License

ISC

---

*Not affiliated with or endorsed by MITRE Corporation.*
