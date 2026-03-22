# MITRE ATT&CK Explorer — Design Spec

## Overview

A web UI for exploring MITRE ATT&CK framework data. React + TypeScript frontend with Vercel serverless API functions backed by PostgreSQL. Data is seeded from STIX JSON via `mitreattack-python`.

**Phase 1**: Exploration — browse, search, and explore techniques, groups, software, mitigations, tactics, campaigns, data sources, sectors, and relationships. Includes ATT&CK matrix heatmap view, D3 relationship graph, and CSV export.
**Phase 2** (future): Threat mapping — map threats to your org, build coverage matrices, track detection capabilities.

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌──────────────┐
│  React SPA  │────▶│  Vercel Serverless│────▶│  PostgreSQL  │
│  (Vite)     │     │  Functions (TS)   │     │  (Neon)      │
└─────────────┘     └──────────────────┘     └──────────────┘
                                                    ▲
                                              ┌─────┴──────┐
                                              │ Seed Script │
                                              │  (Python)   │
                                              └─────┬──────┘
                                                    ▲
                                              ┌─────┴──────┐
                                              │ STIX JSON  │
                                              │ (48MB)     │
                                              └────────────┘
```

- **Frontend**: React 18, TypeScript, Tailwind CSS, React Router v6, TanStack Query, Recharts, D3.js (relationship graph + matrix heatmap)
- **API**: Vercel serverless TypeScript functions, raw SQL via `@vercel/postgres` (uses Neon serverless driver with built-in connection pooling)
- **Database**: Vercel Postgres (Neon) for production, local PostgreSQL for dev
- **Seed pipeline**: Python script using `mitreattack-python` to extract STIX data → insert into PostgreSQL
- **Deployment**: Vercel (monorepo — frontend + API + seed script)

## Database Schema

### Entity Tables

```sql
-- Metadata: tracks ATT&CK version and seed history
CREATE TABLE seed_metadata (
  id SERIAL PRIMARY KEY,
  attack_version VARCHAR(20) NOT NULL,       -- e.g. "16.1"
  domain VARCHAR(30) NOT NULL DEFAULT 'enterprise-attack',
  stix_bundle_hash VARCHAR(64),              -- SHA-256 of source STIX JSON
  source_url VARCHAR(512),                   -- download URL used
  seeded_at TIMESTAMPTZ DEFAULT now(),
  entity_counts JSONB,                       -- {"techniques": 691, "groups": 172, ...}
  seed_duration_ms INTEGER,
  seeded_by VARCHAR(100) DEFAULT 'manual'    -- "manual" or "ci-pipeline"
);

CREATE TABLE tactics (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,               -- identity from STIX bundle
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- TA0001
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  sort_order INTEGER NOT NULL DEFAULT 0,      -- kill chain phase ordering
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,                   -- MITRE's creation date
  stix_modified TIMESTAMPTZ,                  -- MITRE's last modified date
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE techniques (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- T1059, T1059.001
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  platforms TEXT[],                            -- ['Windows', 'Linux', 'macOS']
  is_subtechnique BOOLEAN DEFAULT false,
  parent_technique_id UUID REFERENCES techniques(id),
  detection TEXT,
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  revoked_by_stix_id VARCHAR(255),            -- points to replacing technique if revoked
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE threat_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- G0016
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  aliases TEXT[],
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE attack_software (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- S0039
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  type VARCHAR(20) NOT NULL CHECK (type IN ('malware', 'tool')),
  platforms TEXT[],
  aliases TEXT[],
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE mitigations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- M1031
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE campaigns (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- C0024
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  aliases TEXT[],
  first_seen TIMESTAMPTZ,                     -- when campaign activity started
  last_seen TIMESTAMPTZ,                      -- when campaign activity ended
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE data_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  attack_id VARCHAR(20) UNIQUE NOT NULL,      -- DS0009
  name VARCHAR(255) NOT NULL,
  description TEXT,
  url VARCHAR(512),
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE data_components (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stix_id VARCHAR(255) UNIQUE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  data_source_id UUID REFERENCES data_sources(id) ON DELETE CASCADE,
  is_revoked BOOLEAN DEFAULT false,
  is_deprecated BOOLEAN DEFAULT false,
  domain VARCHAR(30) DEFAULT 'enterprise-attack',
  stix_created TIMESTAMPTZ,
  stix_modified TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE sectors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(100) UNIQUE NOT NULL,
  slug VARCHAR(100) UNIQUE NOT NULL,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);
```

### Relationship Tables

```sql
CREATE TABLE technique_tactics (
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  tactic_id UUID REFERENCES tactics(id) ON DELETE CASCADE,
  PRIMARY KEY (technique_id, tactic_id)
);

CREATE TABLE group_techniques (
  group_id UUID REFERENCES threat_groups(id) ON DELETE CASCADE,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  description TEXT,                           -- procedure example
  PRIMARY KEY (group_id, technique_id)
);

CREATE TABLE group_software (
  group_id UUID REFERENCES threat_groups(id) ON DELETE CASCADE,
  software_id UUID REFERENCES attack_software(id) ON DELETE CASCADE,
  description TEXT,
  PRIMARY KEY (group_id, software_id)
);

CREATE TABLE software_techniques (
  software_id UUID REFERENCES attack_software(id) ON DELETE CASCADE,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  description TEXT,                           -- procedure example
  PRIMARY KEY (software_id, technique_id)
);

CREATE TABLE mitigation_techniques (
  mitigation_id UUID REFERENCES mitigations(id) ON DELETE CASCADE,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  description TEXT,
  PRIMARY KEY (mitigation_id, technique_id)
);

CREATE TABLE technique_data_components (
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  data_component_id UUID REFERENCES data_components(id) ON DELETE CASCADE,
  PRIMARY KEY (technique_id, data_component_id)
);

CREATE TABLE campaign_techniques (
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  description TEXT,
  PRIMARY KEY (campaign_id, technique_id)
);

CREATE TABLE campaign_software (
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  software_id UUID REFERENCES attack_software(id) ON DELETE CASCADE,
  description TEXT,
  PRIMARY KEY (campaign_id, software_id)
);

CREATE TABLE group_campaigns (
  group_id UUID REFERENCES threat_groups(id) ON DELETE CASCADE,
  campaign_id UUID REFERENCES campaigns(id) ON DELETE CASCADE,
  description TEXT,
  PRIMARY KEY (group_id, campaign_id)
);

CREATE TABLE group_sectors (
  group_id UUID REFERENCES threat_groups(id) ON DELETE CASCADE,
  sector_id UUID REFERENCES sectors(id) ON DELETE CASCADE,
  source VARCHAR(10) DEFAULT 'auto',          -- 'auto' or 'manual'
  matched_keywords TEXT[],                    -- audit trail for auto-tagging
  PRIMARY KEY (group_id, sector_id)
);
```

### Indexes

```sql
-- Full-text search
CREATE INDEX idx_techniques_search ON techniques USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
CREATE INDEX idx_threat_groups_search ON threat_groups USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
CREATE INDEX idx_software_search ON attack_software USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
CREATE INDEX idx_mitigations_search ON mitigations USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
CREATE INDEX idx_campaigns_search ON campaigns USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));
CREATE INDEX idx_data_sources_search ON data_sources USING GIN (to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, '')));

-- Full-text on procedure examples (relationship descriptions)
CREATE INDEX idx_gt_description ON group_techniques USING GIN (to_tsvector('english', COALESCE(description, '')));
CREATE INDEX idx_st_description ON software_techniques USING GIN (to_tsvector('english', COALESCE(description, '')));
CREATE INDEX idx_ct_description ON campaign_techniques USING GIN (to_tsvector('english', COALESCE(description, '')));

-- Lookup indexes
CREATE INDEX idx_techniques_attack_id ON techniques(attack_id);
CREATE INDEX idx_threat_groups_attack_id ON threat_groups(attack_id);
CREATE INDEX idx_software_attack_id ON attack_software(attack_id);
CREATE INDEX idx_mitigations_attack_id ON mitigations(attack_id);
CREATE INDEX idx_campaigns_attack_id ON campaigns(attack_id);
CREATE INDEX idx_data_sources_attack_id ON data_sources(attack_id);
CREATE INDEX idx_techniques_platforms ON techniques USING GIN (platforms);
CREATE INDEX idx_techniques_parent ON techniques(parent_technique_id);
CREATE INDEX idx_software_type ON attack_software(type);
CREATE INDEX idx_techniques_parent_only ON techniques(id) WHERE is_subtechnique = false;
CREATE INDEX idx_tactics_sort ON tactics(sort_order);

-- Foreign key indexes on relationship tables
CREATE INDEX idx_gt_group ON group_techniques(group_id);
CREATE INDEX idx_gt_technique ON group_techniques(technique_id);
CREATE INDEX idx_gs_group ON group_software(group_id);
CREATE INDEX idx_gs_software ON group_software(software_id);
CREATE INDEX idx_st_software ON software_techniques(software_id);
CREATE INDEX idx_st_technique ON software_techniques(technique_id);
CREATE INDEX idx_mt_mitigation ON mitigation_techniques(mitigation_id);
CREATE INDEX idx_mt_technique ON mitigation_techniques(technique_id);
CREATE INDEX idx_tdc_technique ON technique_data_components(technique_id);
CREATE INDEX idx_tdc_component ON technique_data_components(data_component_id);
CREATE INDEX idx_ct_campaign ON campaign_techniques(campaign_id);
CREATE INDEX idx_ct_technique ON campaign_techniques(technique_id);
CREATE INDEX idx_cs_campaign ON campaign_software(campaign_id);
CREATE INDEX idx_cs_software ON campaign_software(software_id);
CREATE INDEX idx_gc_group ON group_campaigns(group_id);
CREATE INDEX idx_gc_campaign ON group_campaigns(campaign_id);
CREATE INDEX idx_gsec_group ON group_sectors(group_id);
CREATE INDEX idx_gsec_sector ON group_sectors(sector_id);
CREATE INDEX idx_tt_technique ON technique_tactics(technique_id);
CREATE INDEX idx_tt_tactic ON technique_tactics(tactic_id);
CREATE INDEX idx_dc_source ON data_components(data_source_id);
CREATE INDEX idx_campaigns_first_seen ON campaigns(first_seen);
CREATE INDEX idx_campaigns_last_seen ON campaigns(last_seen);
CREATE INDEX idx_gsec_keywords ON group_sectors USING GIN (matched_keywords);
```

## API Layer

Vercel serverless TypeScript functions. Raw SQL with parameterized queries via `@vercel/postgres`. No ORM.

### Shared Middleware (`api/_lib/`)

- **`db.ts`** — Unified query interface abstracting `@vercel/postgres` (Neon serverless driver for production) and `pg` (for local dev). Both accept the same parameterized query syntax.
- **`validate.ts`** — Input validation using `zod`:
  - `attackId`: regex `^(TA|T|G|S|M|C|DS)\d{4}(\.\d{3})?$`
  - `slug`: regex `^[a-z0-9-]+$`
  - `q` / `search`: max 200 chars, min 3 chars
  - `platform`: allowlist (`Windows`, `Linux`, `macOS`, `IaaS`, `SaaS`, etc.)
  - `type`: enum `malware | tool`
  - `page`: positive integer, max 1000
  - `limit`: positive integer, silently clamped 1-200
  - `sort`: allowlist per endpoint
  - `order`: `asc | desc`
  - `entityType` (export): allowlist `techniques | groups | software | mitigations | campaigns | data_sources | tactics | sectors`
  - `format` (export): enum `csv | json`
- **`middleware.ts`** — Shared wrapper for all handlers:
  - Enforces `GET`-only (returns 405 for other methods)
  - Runs zod validation on params/query
  - Catches errors and returns sanitized `{ error: "Internal server error", code: "INTERNAL_ERROR" }` for 500s (raw errors logged server-side only)
  - Sets `Cache-Control` headers (see Caching section)
  - Sets `statement_timeout` on DB queries (5 seconds)
- **`queries.ts`** — Reusable parameterized query builders. Search queries use `plainto_tsquery()` (never raw `to_tsquery()`) to prevent tsquery syntax injection.
- **`types.ts`** — Shared TypeScript interfaces.

### Endpoints

| Method | Route | Description | Params |
|--------|-------|-------------|--------|
| GET | `/api/v1/dashboard` | Stats, top groups, tactic distribution, sector breakdown, ATT&CK version | — |
| GET | `/api/v1/techniques` | Paginated technique list (parents with nested sub-techniques) | `search`, `tactic`, `platform`, `page`, `limit`, `sort`, `order`, `include_deprecated` |
| GET | `/api/v1/techniques/:attackId` | Technique detail + related groups, software, mitigations, data components, sub-techniques, procedure examples | — |
| GET | `/api/v1/groups` | Paginated group list | `search`, `sector`, `page`, `limit`, `sort`, `order` |
| GET | `/api/v1/groups/:attackId` | Group detail + related techniques, software, campaigns, sectors | — |
| GET | `/api/v1/software` | Paginated software list | `search`, `type`, `platform`, `page`, `limit`, `sort`, `order` |
| GET | `/api/v1/software/:attackId` | Software detail + related techniques, groups, campaigns | — |
| GET | `/api/v1/mitigations` | Paginated mitigations list | `search`, `page`, `limit`, `sort`, `order` |
| GET | `/api/v1/mitigations/:attackId` | Mitigation detail + related techniques | — |
| GET | `/api/v1/campaigns` | Paginated campaigns list | `search`, `page`, `limit`, `sort`, `order` |
| GET | `/api/v1/campaigns/:attackId` | Campaign detail + related techniques, software, groups, timeline | — |
| GET | `/api/v1/tactics` | All tactics with technique counts (ordered by kill chain phase) | — |
| GET | `/api/v1/tactics/:attackId` | Tactic detail + all techniques | — |
| GET | `/api/v1/data-sources` | All data sources with component counts | `search` |
| GET | `/api/v1/data-sources/:attackId` | Data source detail + components + linked techniques | — |
| GET | `/api/v1/sectors` | All sectors with group counts | — |
| GET | `/api/v1/sectors/:slug` | Sector detail + all groups | — |
| GET | `/api/v1/relationships/:attackId` | All entities connected to a given entity (graph data) | `limit` |
| GET | `/api/v1/matrix` | Full matrix data: tactics (columns) x techniques (rows) with group usage counts | `domain` |
| GET | `/api/v1/search` | Global full-text search across all entity types | `q` |
| GET | `/api/v1/export/:entityType` | Bulk export | `format` (csv/json) |
| GET | `/api/v1/procedures` | Search procedure examples across all relationships | `q`, `page`, `limit` |

### Response Format

**Success (list):**
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 50,
    "total": 691,
    "totalPages": 14
  }
}
```

**Success (search):** Intentionally different — returns grouped results across entity types:
```json
{
  "techniques": [...],
  "groups": [...],
  "software": [...],
  "mitigations": [...],
  "campaigns": [...],
  "data_sources": [...]
}
```

**Error:**
```json
{
  "error": "Resource not found",
  "code": "NOT_FOUND"
}
```

**Error conventions:**
- `400` — invalid query params. Invalid `limit` silently clamped. Truly invalid params (bad regex) return 400.
- `404` — entity not found by `attackId`
- `405` — non-GET method attempted
- `429` — rate limit exceeded
- `500` — sanitized generic error (raw details logged server-side only, never sent to client)

**Pagination:**
- Defaults: page=1, limit=50, max limit=200 (silently clamped)
- Sort defaults: `name` ascending for most entities, `sort_order` for tactics
- Detail endpoints return relationships pre-joined
- No auth for Phase 1 — read-only public data

### Caching

All data changes only on manual re-seed (~2x/year). Aggressive caching:
- **List/detail endpoints**: `Cache-Control: public, s-maxage=3600, stale-while-revalidate=86400` (1 hour CDN, 1 day stale)
- **Dashboard/matrix**: `Cache-Control: public, s-maxage=1800, stale-while-revalidate=86400`
- **Search/procedures**: `Cache-Control: public, s-maxage=300` (5 min)

### Rate Limiting

Implemented via Vercel Edge Middleware or `@vercel/kv`:
- **Global**: 300 req/min per IP
- **Search/procedures**: 60 req/min per IP (more expensive queries)
- **Export**: 10 req/min per IP
- Returns `429` with `Retry-After` header when exceeded

## Frontend Architecture

### Tech Stack

- React 18 + TypeScript
- React Router v6 — page-based navigation
- TanStack Query — server state caching
- Tailwind CSS — dark theme
- Recharts — dashboard charts
- D3.js — relationship graph + matrix heatmap
- DOMPurify — sanitize rendered descriptions
- Vite — dev server + build

### Layout

Persistent sidebar navigation (always visible):

```
┌──────────┬──────────────────────────────────────┐
│          │  Search Bar                [v16.1]   │
│  MITRE   ├──────────────────────────────────────┤
│  ATT&CK  │                                      │
│          │  Page Content                         │
│ Dashboard│  (stats, tables, detail views)        │
│ Matrix   │                                       │
│ Techniques                                       │
│ Groups   │                                       │
│ Campaigns│                                       │
│ Software │                                       │
│ Data Srcs│                                       │
│ Mitigations                                      │
│ Tactics  │                                       │
│ Sectors  │                                       │
│ Relations│                                       │
│ ──────── │                                       │
│ Reports  │  (CTI feeds)                          │
│ IOCs     │                                       │
│ Sigma    │                                       │
│ Feed Status                                      │
│          │                                       │
└──────────┴──────────────────────────────────────┘
```

ATT&CK version displayed in header (from `seed_metadata`).

### Project Structure

```
src/
  components/
    layout/           Sidebar, PageHeader, SearchBar
    shared/           DataTable, StatCard, Badge, Pagination, EntityLink, DeprecatedBadge
    charts/           TacticBarChart, SectorPieChart, GroupTechniqueChart, CampaignTimeline
    graph/            ForceGraph, GraphNode, GraphEdge, GraphTooltip
    matrix/           MatrixGrid, MatrixCell, MatrixLegend
  pages/
    Dashboard.tsx        stats + charts + quick access links
    Matrix.tsx           ATT&CK Navigator-style heatmap
    TechniquesList.tsx   filterable table with nested sub-techniques
    TechniqueDetail.tsx  full info + data sources + procedure examples + related entities
    GroupsList.tsx        filterable table with sector tags
    GroupDetail.tsx       full info + techniques + campaigns + software
    CampaignsList.tsx    filterable table with timeline
    CampaignDetail.tsx   full info + techniques + software + groups + temporal data
    SoftwareList.tsx     filterable table
    SoftwareDetail.tsx   full info + related techniques/groups
    DataSourcesList.tsx  data sources with component counts
    DataSourceDetail.tsx data source + components + linked techniques
    MitigationsList.tsx  filterable table
    MitigationDetail.tsx full info + related techniques
    TacticsList.tsx      all tactics in kill chain order with technique counts
    TacticDetail.tsx     tactic + all its techniques
    SectorsList.tsx      sectors with group counts
    SectorDetail.tsx     sector + all groups
    Relationships.tsx    D3 force graph entity explorer
    Search.tsx           global search results
    ReportsList.tsx      threat reports feed
    IocsList.tsx         IOC feed
    SigmaList.tsx        Sigma detection rules
    FeedStatus.tsx       ingestion health dashboard
  hooks/
    useApi.ts            TanStack Query wrappers for each endpoint
  lib/
    api.ts               fetch helpers, base URL config
    types.ts             TypeScript interfaces matching API responses
    sanitize.ts          DOMPurify wrapper for description rendering
  App.tsx                Router + Sidebar layout
```

### Routes

| Path | Page | Description |
|------|------|-------------|
| `/` | Dashboard | Stats, charts, quick access |
| `/matrix` | Matrix | ATT&CK Navigator-style heatmap |
| `/techniques` | TechniquesList | Filterable table with nested sub-techniques |
| `/techniques/:attackId` | TechniqueDetail | Full detail + data sources + procedures + relationships |
| `/groups` | GroupsList | Filterable table with sector tags |
| `/groups/:attackId` | GroupDetail | Full detail + campaigns + relationships |
| `/campaigns` | CampaignsList | Filterable table with timeline |
| `/campaigns/:attackId` | CampaignDetail | Full detail + temporal data + relationships |
| `/software` | SoftwareList | Filterable table |
| `/software/:attackId` | SoftwareDetail | Full detail + relationships |
| `/data-sources` | DataSourcesList | Data sources + component counts |
| `/data-sources/:attackId` | DataSourceDetail | Source + components + linked techniques |
| `/mitigations` | MitigationsList | Filterable table |
| `/mitigations/:attackId` | MitigationDetail | Full detail + relationships |
| `/tactics` | TacticsList | Kill chain ordered tactics |
| `/tactics/:attackId` | TacticDetail | Tactic + techniques |
| `/sectors` | SectorsList | All sectors |
| `/sectors/:slug` | SectorDetail | Sector + groups |
| `/relationships` | Relationships | D3 force graph explorer |
| `/search` | Search | Global search results |
| `/reports` | ReportsList | Threat intelligence reports feed |
| `/iocs` | IocsList | IOC feed with type/source filters |
| `/sigma` | SigmaList | Sigma detection rules by technique |
| `/feed-status` | FeedStatus | Ingestion health dashboard |

**Deep-linking**: All filter, search, sort, and pagination state is reflected in URL query params so analysts can share filtered views with their team.

### Key Components

- **DataTable** — reusable across all list pages. Props: columns, data, filters, search, sorting, pagination. Renders a table with sticky header, row click → navigate to detail. Supports `sort` and `order` query params.
- **EntityLink** — clickable badge linking to detail page. Color-coded by entity type (teal=technique, orange=group, purple=software, green=mitigation, blue=campaign, pink=data source).
- **DeprecatedBadge** — visual warning badge shown on revoked/deprecated entities. Links to the replacing entity if available.
- **StatCard** — number + label + optional trend. Used on dashboard.
- **SearchBar** — global search in header. Debounced input (300ms), min 3 chars, navigates to `/search?q=`.
- **Badge** — tag pills for platforms, sectors, tactic names.
- **MatrixGrid** — ATT&CK matrix heatmap. Tactics as columns (kill chain order), techniques as rows. Cell color intensity based on group usage count. Clickable cells navigate to technique detail.
- **CampaignTimeline** — horizontal timeline showing campaign `first_seen` to `last_seen` ranges.

### Design System

- **Dark theme** — navy/dark blue background (#1a1a2e, #16213e), light text (#ccd6f6)
- **Accent colors** — teal (#64ffda) technique, orange (#f97316) group, purple (#a78bfa) software, green (#34d399) mitigation, blue (#60a5fa) campaign, pink (#f472b6) data source, yellow (#fbbf24) tactic
- **Typography** — Inter or system font stack, 14px base
- **Cards** — subtle border (#2a2a4a), rounded corners (8px)
- **Tables** — alternating row shading, hover highlight, sticky header
- **Deprecated entities** — muted opacity (0.6) with strikethrough on name + badge

### Keyboard Navigation

Power-user shortcuts:
- `/` — focus global search
- `Esc` — close/blur current focus
- `↑↓` — navigate table rows
- `Enter` — open selected row's detail page

## ATT&CK Matrix View

The Matrix page (`/matrix`) renders the classic ATT&CK Navigator-style heatmap:

### Layout
- **Columns**: Tactics in kill chain order (left-to-right: Reconnaissance → Impact)
- **Rows**: Techniques under each tactic
- **Sub-techniques**: Collapsed by default, expand on click
- **Cell color**: Intensity based on number of groups using that technique (white=0, light teal=few, dark teal=many)
- **Hover**: Shows technique name, ATT&CK ID, group count
- **Click**: Navigates to technique detail page

### Data
- Served by `/api/v1/matrix` endpoint which returns the full tactic→technique mapping with group usage counts pre-computed
- Single API call loads the entire matrix (cached aggressively)

### Interactions
- Click a tactic header to navigate to tactic detail
- Click any technique cell to navigate to technique detail
- Toggle sub-techniques visibility
- Filter by platform (dropdown above matrix)

## Relationship Explorer

The Relationships page (`/relationships`) uses a **D3.js force-directed graph** to visualize connections between entities.

### UX Flow

1. User lands on `/relationships` with an empty graph and a **search/autocomplete input** at the top
2. User types an entity name (e.g. "APT29") — autocomplete suggests matches from all entity types via `/api/v1/search?q=`
3. User selects an entity → graph renders with the selected entity as the center node
4. Connected entities appear as nodes radiating outward, grouped and color-coded by type
5. User can click any node to expand its connections (adds to the graph, doesn't replace)
6. Hover on a node shows a tooltip with name, attack_id, and type
7. Hover on an edge shows the relationship description (procedure example)
8. Nodes are draggable for manual layout adjustment

### Graph Data Shape

The `/api/v1/relationships/:attackId` endpoint returns:
```json
{
  "center": { "attackId": "G0016", "name": "APT29", "type": "group" },
  "nodes": [
    { "attackId": "T1059", "name": "Command and Scripting Interpreter", "type": "technique" },
    { "attackId": "S0039", "name": "Net", "type": "software" },
    { "attackId": "C0024", "name": "SolarWinds Compromise", "type": "campaign" }
  ],
  "edges": [
    { "source": "G0016", "target": "T1059", "relationship": "uses", "description": "APT29 uses..." },
    { "source": "G0016", "target": "C0024", "relationship": "attributed-to", "description": "..." }
  ],
  "truncated": false
}
```

### Node Colors
- Technique: teal (#64ffda)
- Group: orange (#f97316)
- Software: purple (#a78bfa)
- Mitigation: green (#34d399)
- Campaign: blue (#60a5fa)
- Data Source: pink (#f472b6)
- Tactic: yellow (#fbbf24)

### Performance
- Initial expansion limited to direct connections (1 hop)
- Max 200 nodes enforced **server-side** — `limit` param (default 200). If truncated, response includes `"truncated": true` so the UI can show a "showing top 200 connections — use filters to narrow" message
- Use D3 force simulation with collision detection to prevent overlap
- All description/text rendering uses `textContent` (never `innerHTML`) to prevent XSS

## Sub-Technique Display

Sub-techniques are displayed **nested under their parent** on the techniques list page:

- Parent techniques show as normal rows with an expand/collapse chevron
- Clicking the chevron reveals sub-techniques as indented child rows
- Sub-technique rows show a `T1059.001` style ID with visual indentation
- The parent row shows a count badge: "7 sub-techniques"
- Filtering/searching includes sub-techniques — if a sub-technique matches, its parent auto-expands
- The `/api/v1/techniques` endpoint returns parent techniques at the top level with a `sub_techniques` array nested inside each parent:

```json
{
  "attackId": "T1059",
  "name": "Command and Scripting Interpreter",
  "sub_techniques": [
    { "attackId": "T1059.001", "name": "PowerShell", ... },
    { "attackId": "T1059.002", "name": "AppleScript", ... }
  ]
}
```

## Technique Detail: Procedure Examples

Technique detail pages prominently display **procedure examples** — the specific ways groups and software use a technique. These are sourced from the `description` field in `group_techniques` and `software_techniques` junction tables.

### Display
- Dedicated "Procedure Examples" section on technique detail page
- Grouped by: "Used by Groups", "Used by Software", and "Used in Campaigns"
- Each entry shows: entity name (as EntityLink) + procedure description text
- Searchable via `/api/v1/procedures?q=` endpoint

### Technique Detail also shows:
- **Data Sources**: Which data sources and components detect this technique (from `technique_data_components`)
- **Mitigations**: How to prevent this technique
- **Related Groups**: Who uses it (with procedure examples)
- **Related Software**: What implements it (with procedure examples)
- **Related Campaigns**: Which campaigns used it
- **Sub-techniques**: If parent technique

## Data Seeding Pipeline

### Structure

```
seed/
  seed.py              main script — orchestrates full pipeline
  extract.py           loads STIX via mitreattack-python, extracts all entities + relationships
  sector_extractor.py  keyword extraction from group descriptions → sector tags
  verify.py            post-seed verification — counts, integrity checks, report
  schema.sql           CREATE TABLE statements, indexes, full-text search config
  sectors.json         curated sector keyword mappings
```

### Sector Keyword Map (sectors.json)

Uses word-boundary regex matching (`\b` anchors) to prevent false positives on short keywords like "IT".

```json
{
  "Government": ["government", "diplomatic", "political"],
  "Financial": ["financial", "banking", "fintech", "cryptocurrency"],
  "Healthcare": ["healthcare", "medical", "pharmaceutical", "hospital"],
  "Defense": ["defense", "military", "aerospace", "aviation"],
  "Technology": ["technology", "software", "\\bIT\\b", "cloud"],
  "Energy": ["energy", "\\boil\\b", "\\bgas\\b", "power grid", "utility", "SCADA"],
  "Telecommunications": ["telecom", "telecommunications", "\\bISP\\b"],
  "Education": ["education", "university", "academic", "research"],
  "Manufacturing": ["manufacturing", "industrial", "supply chain"],
  "Retail": ["retail", "e-commerce", "point-of-sale"],
  "Transportation": ["transportation", "shipping", "logistics", "maritime"],
  "Media": ["media", "journalism", "news", "entertainment"]
}
```

Note: "state-sponsored" removed from Government — it describes actor origin, not target sector.

### Flow

1. `schema.sql` → `TRUNCATE ... CASCADE` all tables (preserves schema, safer than DROP)
2. `extract.py` → reads `enterprise-attack.json` via `MitreAttackData`
   - Extracts all entity types including campaigns, data sources, data components
   - Preserves `stix_id`, `stix_created`, `stix_modified` from STIX objects
   - Stores revoked/deprecated objects with flags set (does NOT filter them out)
   - Extracts `revoked-by` relationships for revoked techniques
   - Reads ATT&CK version from STIX bundle metadata
3. `sector_extractor.py` → scans group descriptions against keyword map
   - Uses word-boundary regex matching
   - Records `matched_keywords` for audit trail
4. `seed.py` → connects via `DATABASE_URL`, inserts all data in a single transaction
   - Writes `seed_metadata` record with version, hash, counts, duration
5. `verify.py` → post-seed verification:
   - Counts all entities and compares to STIX source counts
   - Validates all foreign keys resolve
   - Checks for orphaned relationships
   - Outputs summary report

### STIX Download Integrity

When `--update` flag is used:
- Downloads from official source: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- Computes SHA-256 hash of downloaded file
- Stores hash in `seed_metadata` for audit
- Pins to specific ATT&CK version — requires explicit `--version` flag to change
- Logs download source, hash, and version

### Safety

- **`--confirm-destructive` flag required for production** seeding. Without it, seed script refuses to run against any `DATABASE_URL` containing `neon` or `vercel`.
- Entire seed runs in a single transaction — partial seed is impossible
- `seed_metadata` table is never truncated — provides full audit history

### Commands

```bash
npm run seed                        # seed local PostgreSQL
npm run seed:prod -- --confirm-destructive   # seed Vercel Postgres
npm run seed:update                 # download fresh STIX JSON + seed local
```

### Seed Script Dependencies (`seed/requirements.txt`)

```
mitreattack-python==5.4.3
psycopg[binary]==3.2.6
requests==2.32.5
```

Uses `psycopg` v3 (not `psycopg2-binary`) for improved security and async support. The `npm run seed` scripts use the project venv:
```json
{
  "seed": "./venv/bin/python seed/seed.py",
  "seed:prod": "DATABASE_URL=$POSTGRES_URL ./venv/bin/python seed/seed.py",
  "seed:update": "./venv/bin/python seed/seed.py --update"
}
```

## Deployment

### Vercel Configuration

```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "crons": [
    { "path": "/cron/ingest-otx", "schedule": "*/30 * * * *" },
    { "path": "/cron/ingest-abuse-ch", "schedule": "0 2 * * *" },
    { "path": "/cron/ingest-cisa-kev", "schedule": "0 3 * * *" },
    { "path": "/cron/ingest-rss", "schedule": "0 */6 * * *" },
    { "path": "/cron/sync-d3fend", "schedule": "0 6 1 * *" }
  ],
  "rewrites": [
    { "source": "/api/(.*)", "destination": "/api/$1" },
    { "source": "/(.*)", "destination": "/index.html" }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-XSS-Protection", "value": "0" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" },
        { "key": "Content-Security-Policy", "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'" }
      ]
    }
  ]
}
```

### Project Root Structure

```
mitre/
  api/                    Vercel serverless functions (filesystem routing)
    v1/
      dashboard.ts                      GET /api/v1/dashboard
      matrix.ts                         GET /api/v1/matrix
      search.ts                         GET /api/v1/search
      export/
        [entityType].ts                 GET /api/v1/export/:entityType
      procedures.ts                     GET /api/v1/procedures
      techniques/
        index.ts                        GET /api/v1/techniques
        [attackId].ts                   GET /api/v1/techniques/:attackId
      groups/
        index.ts                        GET /api/v1/groups
        [attackId].ts                   GET /api/v1/groups/:attackId
      campaigns/
        index.ts                        GET /api/v1/campaigns
        [attackId].ts                   GET /api/v1/campaigns/:attackId
      software/
        index.ts                        GET /api/v1/software
        [attackId].ts                   GET /api/v1/software/:attackId
      data-sources/
        index.ts                        GET /api/v1/data-sources
        [attackId].ts                   GET /api/v1/data-sources/:attackId
      mitigations/
        index.ts                        GET /api/v1/mitigations
        [attackId].ts                   GET /api/v1/mitigations/:attackId
      tactics/
        index.ts                        GET /api/v1/tactics
        [attackId].ts                   GET /api/v1/tactics/:attackId
      sectors/
        index.ts                        GET /api/v1/sectors
        [slug].ts                       GET /api/v1/sectors/:slug
      relationships/
        [attackId].ts                   GET /api/v1/relationships/:attackId
    _lib/                 shared (not deployed as functions — underscore prefix)
      db.ts               unified query interface (Neon serverless + pg)
      validate.ts         zod schemas for all params
      middleware.ts       method enforcement, error sanitization, caching
      queries.ts          reusable parameterized query builders
      types.ts            shared TypeScript interfaces
      rateLimit.ts        rate limiting via Vercel KV
  cron/                   Vercel Cron jobs for CTI feed ingestion
    ingest-otx.ts                       OTX pulse ingestion (every 30 min)
    ingest-abuse-ch.ts                  ThreatFox + MalwareBazaar (daily)
    ingest-cisa-kev.ts                  CISA KEV (daily)
    ingest-rss.ts                       RSS feed polling (every 6 hours)
    sync-d3fend.ts                      D3FEND ontology sync (monthly)
  .github/workflows/      GitHub Actions for heavy sync jobs
    sync-sigma.yml                      Sigma rules sync (weekly, clones ~1.5GB repo)
    sync-atomic.yml                     Atomic Red Team sync (weekly, clones repo)
  src/                    React frontend
  seed/                   Python seeding pipeline
  data/                   STIX JSON (gitignored)
  venv/                   Python venv (gitignored)
  server/
    dev-server.ts         local Express server for development
  public/
    robots.txt            crawler management
  package.json
  tsconfig.json
  tailwind.config.ts
  vite.config.ts
  vercel.json
  .env.local              DATABASE_URL for local dev (gitignored)
  .gitignore
```

### .gitignore

```
.env
.env.local
.env.production
.env*.local
node_modules/
dist/
venv/
data/
__pycache__/
*.pyc
.vercel/
.superpowers/
```

### Environment Variables

```
DATABASE_URL=postgresql://user:pass@localhost:5432/mitre_attack    # local
# Vercel injects POSTGRES_URL automatically for Vercel Postgres
```

### CORS

Explicit CORS headers set in API middleware:
- **Production**: `Access-Control-Allow-Origin` restricted to the Vercel deployment domain
- **Local dev**: `Access-Control-Allow-Origin: http://localhost:5173` (Vite dev server)
- Phase 2 auth-readiness: never use `*`

### robots.txt

```
User-agent: *
Allow: /
Disallow: /api/
Disallow: /search
Disallow: /relationships
```

Prevents crawlers from hammering API endpoints and dynamic pages.

### Local Development

```bash
Terminal 1: npm run dev          # Vite dev server (React on :5173)
Terminal 2: npm run dev:api      # local Express server (:3001)
Database:   local PostgreSQL via psql
```

**Local API server** (`server/dev-server.ts`): A lightweight Express + tsx server that mirrors Vercel's filesystem routing. It:
- Scans `api/v1/` directory structure and registers routes matching Vercel conventions
- Maps `[param].ts` files to Express `:param` routes
- Uses `pg` package directly (same queries, different connection — `DATABASE_URL` from `.env.local`)
- Runs via `tsx watch` for hot reload

**Vite proxy**: `vite.config.ts` includes a proxy entry to route `/api/*` requests to the local Express server:
```ts
server: {
  proxy: { '/api': 'http://localhost:3001' }
}
```

## CTI Feed Layer

Supplements the static ATT&CK knowledge base with live threat intelligence from open-source feeds. Turns every technique detail page into a live intelligence dashboard.

### CTI Data Sources

#### Tier 1: ATT&CK-mapped, free API, automated ingestion

| Source | What it provides | API | Auth | ATT&CK mapped? | Update freq |
|--------|-----------------|-----|------|----------------|-------------|
| **AlienVault OTX** | Threat pulses with IOCs + technique IDs | REST `https://otx.alienvault.com/api/v1/pulses/subscribed` | Free API key (`X-OTX-API-KEY` header) | Yes (`attack_ids` field, format: `T1059.001`) | Continuous |
| **Sigma Rules** | Detection rules per technique | GitHub `https://github.com/SigmaHQ/sigma` (YAML files) | None | Yes (YAML `tags` field) | Monthly |
| **Atomic Red Team** | Test procedures per technique | GitHub `https://github.com/redcanaryco/atomic-red-team` (YAML) | None | Yes (directory = technique ID) | Continuous |
| **MITRE D3FEND** | Defensive countermeasures per technique | Bulk: `https://d3fend.mitre.org/ontologies/d3fend.json` (full ontology). Per-technique: `https://d3fend.mitre.org/api/offensive-technique/attack/{id}.json` | None | Yes (bidirectional mapping) | 2x/year |
| **CISA KEV** | Known exploited vulnerabilities | Static JSON `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | None | Needs CVE→technique enrichment | Weekly |

#### Tier 2: IOC feeds, indirect ATT&CK mapping via malware family cross-reference

| Source | What it provides | API | Auth |
|--------|-----------------|-----|------|
| **ThreatFox** (abuse.ch) | IOCs linked to malware families | REST `https://threatfox-api.abuse.ch/api/v1/` | Free key (`Auth-Key` header) |
| **MalwareBazaar** (abuse.ch) | Malware samples + signatures | REST `https://mb-api.abuse.ch/api/v1/` | Free key |
| **Malpedia** | Malware family profiles + actor links | REST `https://malpedia.caad.fkie.fraunhofer.de/api/` | Free account token |

All abuse.ch services use a single account: https://auth.abuse.ch/

#### Tier 3: Threat report RSS feeds (technique extraction via regex)

| Source | RSS URL | Notes |
|--------|---------|-------|
| **The DFIR Report** | `https://thedfirreport.com/feed/` | Detailed technique breakdowns per incident |
| **Unit 42** (Palo Alto) | `https://unit42.paloaltonetworks.com/feed/` | + GitHub IOCs |
| **Microsoft MSTIC** | `https://www.microsoft.com/en-us/security/blog/feed/` | Threat intelligence posts |
| **Cisco Talos** | `https://blog.talosintelligence.com/rss/` | + IP blocklist |

### CTI Database Schema

```sql
-- Threat intelligence reports from RSS feeds and OTX pulses
CREATE TABLE threat_reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(512) NOT NULL,
  source VARCHAR(100) NOT NULL,            -- 'otx', 'dfir_report', 'unit42', 'mstic', 'talos'
  url VARCHAR(1024) UNIQUE NOT NULL,       -- deduplication key
  published_at TIMESTAMPTZ,
  summary TEXT,
  raw_content TEXT,                        -- full text for re-extraction
  extracted_technique_ids TEXT[],          -- ['T1059.001', 'T1021.002', ...]
  otx_pulse_id VARCHAR(100),              -- OTX-specific: pulse ID
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()   -- tracks OTX pulse edits via upsert
);

-- IOC entries from ThreatFox, MalwareBazaar, OTX, CISA KEV
CREATE TABLE ioc_entries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  type VARCHAR(50) NOT NULL,               -- 'ip', 'domain', 'url', 'sha256', 'md5', 'cve'
  value VARCHAR(2048) NOT NULL,
  source VARCHAR(100) NOT NULL,            -- 'threatfox', 'malwarebazaar', 'otx', 'cisa_kev'
  malware_family VARCHAR(255),             -- cross-reference against attack_software.name/aliases
  confidence INTEGER,                      -- 0-100 if available
  first_seen TIMESTAMPTZ,
  last_seen TIMESTAMPTZ,
  tags TEXT[],
  source_ref VARCHAR(512),                 -- link back to source entry
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(type, value, source)              -- deduplication
);

-- Sigma detection rules mapped to techniques
CREATE TABLE sigma_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  sigma_id VARCHAR(100) UNIQUE,            -- sigma rule UUID from YAML
  title VARCHAR(512) NOT NULL,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20) NOT NULL, -- T1059.001 (for display even if technique FK missing)
  level VARCHAR(20),                        -- 'low', 'medium', 'high', 'critical'
  status VARCHAR(20),                       -- 'test', 'stable', 'experimental'
  description TEXT,
  logsource_category VARCHAR(100),          -- 'process_creation', 'network_connection', etc.
  logsource_product VARCHAR(100),           -- 'windows', 'linux', 'azure'
  yaml_url VARCHAR(1024),                   -- GitHub raw URL to YAML file
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- Atomic Red Team test procedures mapped to techniques
CREATE TABLE atomic_tests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(512) NOT NULL,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20) NOT NULL,
  test_number INTEGER,                      -- test index within technique
  description TEXT,
  platforms TEXT[],                          -- ['windows', 'linux', 'macos']
  executor_type VARCHAR(50),                -- 'command_prompt', 'powershell', 'bash', 'manual'
  executor_command TEXT,                    -- the actual test command
  cleanup_command TEXT,
  source_url VARCHAR(1024),                 -- GitHub URL
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(attack_technique_id, test_number)  -- stable deduplication key
);

-- D3FEND defensive technique mappings
CREATE TABLE defensive_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id VARCHAR(20) NOT NULL,
  d3fend_id VARCHAR(50) NOT NULL,           -- D3-DA01, etc.
  d3fend_name VARCHAR(255) NOT NULL,
  d3fend_tactic VARCHAR(100),               -- 'Detect', 'Isolate', 'Deceive', 'Evict', 'Restore'
  relationship VARCHAR(50),                 -- 'detects', 'isolates', 'evicts'
  d3fend_url VARCHAR(512),
  created_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(technique_id, d3fend_id)
);

-- Link IOCs to techniques (via malware family → software → technique chain)
CREATE TABLE technique_iocs (
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  ioc_id UUID REFERENCES ioc_entries(id) ON DELETE CASCADE,
  confidence VARCHAR(20) DEFAULT 'inferred', -- 'direct' (OTX attack_ids) or 'inferred' (malware family chain)
  PRIMARY KEY (technique_id, ioc_id)
);

-- Link reports to techniques (via extracted technique IDs)
CREATE TABLE report_techniques (
  report_id UUID REFERENCES threat_reports(id) ON DELETE CASCADE,
  technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  PRIMARY KEY (report_id, technique_id)
);
```

### Feed Sync Log

Backs the Feed Status page and `/api/v1/feed/status` endpoint:

```sql
CREATE TABLE feed_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source VARCHAR(100) NOT NULL,             -- 'otx', 'threatfox', 'malwarebazaar', 'cisa_kev', 'rss', 'sigma', 'atomic', 'd3fend'
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  completed_at TIMESTAMPTZ,
  status VARCHAR(20) NOT NULL DEFAULT 'running',  -- 'success', 'error', 'partial'
  records_inserted INTEGER DEFAULT 0,
  records_skipped INTEGER DEFAULT 0,        -- deduplication skips (UNIQUE conflicts)
  error_message TEXT,
  UNIQUE(source, started_at)
);
```

Every ingestion job writes a `feed_sync_log` entry at start (`status='running'`), updates it on completion (`status='success'`), or on failure (`status='error'` with `error_message`). The Feed Status page queries the latest entry per source.

### CTI Indexes

```sql
CREATE INDEX idx_reports_source ON threat_reports(source);
CREATE INDEX idx_reports_published ON threat_reports(published_at DESC);
CREATE INDEX idx_reports_search ON threat_reports USING GIN (to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(summary, '')));
CREATE INDEX idx_reports_techniques ON threat_reports USING GIN (extracted_technique_ids);
CREATE INDEX idx_iocs_type_value ON ioc_entries(type, value);
CREATE INDEX idx_iocs_source ON ioc_entries(source);
CREATE INDEX idx_iocs_malware ON ioc_entries(malware_family);
CREATE INDEX idx_iocs_first_seen ON ioc_entries(first_seen DESC);
CREATE INDEX idx_sigma_technique ON sigma_rules(technique_id);
CREATE INDEX idx_sigma_level ON sigma_rules(level);
CREATE INDEX idx_atomic_technique ON atomic_tests(technique_id);
CREATE INDEX idx_defensive_technique ON defensive_mappings(technique_id);
CREATE INDEX idx_ti_technique ON technique_iocs(technique_id);
CREATE INDEX idx_rt_technique ON report_techniques(technique_id);
CREATE INDEX idx_rt_report ON report_techniques(report_id);
CREATE INDEX idx_sync_source ON feed_sync_log(source, started_at DESC);
```

### CTI API Endpoints

| Method | Route | Description | Params |
|--------|-------|-------------|--------|
| GET | `/api/v1/techniques/:attackId/intelligence` | All CTI for a technique (top 5 reports, 10 IOCs, all sigma/atomic/d3fend) | `report_limit`, `ioc_limit` |
| GET | `/api/v1/feed/reports` | Latest threat reports across all sources | `source`, `since`, `q`, `page`, `limit`, `sort` |
| GET | `/api/v1/feed/iocs` | Latest IOCs across all sources | `type`, `source`, `malware`, `q`, `since`, `page`, `limit` |
| GET | `/api/v1/feed/sigma` | Sigma rules | `technique`, `level`, `q`, `page`, `limit` |
| GET | `/api/v1/feed/atomic` | Atomic Red Team tests | `technique`, `platform`, `page`, `limit` |
| GET | `/api/v1/feed/status` | Feed ingestion status: last sync time per source, counts, errors | — |
| POST | `/api/v1/feed/:source/sync` | Manual trigger sync (authenticated with `CRON_SECRET`) | — |

### CTI Ingestion Pipeline

Scheduled jobs via **Vercel Cron** (or GitHub Actions for heavier tasks):

**Vercel Cron jobs** (lightweight API polling, fits within serverless execution limits):
```
cron/
  ingest-otx.ts          polls OTX /pulses/subscribed → extracts attack_ids → upserts reports + IOCs
  ingest-abuse-ch.ts     polls ThreatFox + MalwareBazaar → inserts IOCs, cross-refs malware families
  ingest-cisa-kev.ts     fetches CISA KEV JSON → inserts CVE IOCs
  ingest-rss.ts          polls all RSS feeds → extracts technique IDs via regex → inserts reports
  sync-d3fend.ts         downloads D3FEND ontology dump → upserts defensive_mappings
```

**GitHub Actions** (heavy sync jobs that exceed Vercel serverless limits — git clones ~1.5GB repos):
```
.github/workflows/
  sync-sigma.yml         clones SigmaHQ repo → parses YAML → upserts sigma_rules via DATABASE_URL
  sync-atomic.yml        clones Atomic Red Team repo → parses YAML → upserts atomic_tests via DATABASE_URL
```

#### Schedule

| Job | Frequency | Runner | Schedule |
|-----|-----------|--------|----------|
| `ingest-otx` | Every 30 min | Vercel Cron | `*/30 * * * *` |
| `ingest-abuse-ch` | Daily 02:00 UTC | Vercel Cron | `0 2 * * *` |
| `ingest-cisa-kev` | Daily 03:00 UTC | Vercel Cron | `0 3 * * *` |
| `ingest-rss` | Every 6 hours | Vercel Cron | `0 */6 * * *` |
| `sync-d3fend` | Monthly (1st, 06:00 UTC) | Vercel Cron | `0 6 1 * *` |
| `sync-sigma` | Weekly (Sunday 04:00 UTC) | **GitHub Actions** | `cron: '0 4 * * 0'` |
| `sync-atomic` | Weekly (Sunday 05:00 UTC) | **GitHub Actions** | `cron: '0 5 * * 0'` |

Sigma and Atomic syncs cannot run in Vercel serverless — the repos are ~1.5GB each, exceeding Vercel's 512MB `/tmp` limit and 60s Pro execution timeout. GitHub Actions provides full VM with disk and no timeout constraints.

#### OTX Ingestion Details

- **Endpoint**: `GET /api/v1/pulses/subscribed?modified_since={last_sync_timestamp}&limit=50`
- **Pagination**: Response includes `next` cursor URL — follow until exhausted or reaching already-seen records
- **Cursor persistence**: Store timestamp of last successfully ingested pulse in `feed_sync_log` metadata. Use as `modified_since` param on next run.
- **ATT&CK IDs**: Available in `attack_ids` array, already in correct `T1059.001` format — no normalization needed
- **Upsert strategy**: `ON CONFLICT (url) DO UPDATE SET summary = EXCLUDED.summary, extracted_technique_ids = EXCLUDED.extracted_technique_ids` to handle pulse edits
- **Rate budget**: 10,000 req/day. Track per-run request count, abort gracefully at 200/run to leave headroom. Surface budget usage in feed status.

#### abuse.ch Query Bodies

ThreatFox and MalwareBazaar use POST with JSON body — the `query` field determines the action:

**ThreatFox** — get recent IOCs:
```json
POST https://threatfox-api.abuse.ch/api/v1/
Header: Auth-Key: <key>
Body: {"query": "get_iocs", "days": 1}
```

**MalwareBazaar** — get recent samples:
```json
POST https://mb-api.abuse.ch/api/v1/
Header: Auth-Key: <key>
Body: {"query": "get_recent", "selector": "100"}
```

Note: Both APIs may return new IOC types beyond the documented ones (e.g., `btc_address`, `ja3_fingerprint`). The `ioc_entries.type` column has no CHECK constraint — treats type as an open enum to avoid ingestion failures when upstream adds new types.

#### D3FEND Sync Details

Monthly sync uses the **ontology dump** (single 2MB download) instead of per-technique API calls (which would require 700+ individual requests):
```
GET https://d3fend.mitre.org/ontologies/d3fend.json
```
Parse the OWL/JSON-LD to extract all offensive→defensive technique mappings. The per-technique endpoint (`/api/offensive-technique/attack/{id}.json`) is used only for on-demand lookups, not bulk sync.

If the download fails, existing mappings are preserved — the job never deletes rows before confirming new data is available.

#### CISA KEV Integration

CISA KEV provides CVEs, not ATT&CK technique mappings. There is no authoritative automated CVE→ATT&CK mapping. KEV entries are stored as IOCs with `type='cve'` for reference but are **not linked to techniques** in Phase 1. Technique linking is deferred to Phase 2 when a curated mapping table or NVD enrichment source can be evaluated.

#### Technique ID Extraction (RSS feeds)

For Tier 3 RSS feeds, technique IDs are extracted from report text:
- Primary: regex `T\d{4}(\.\d{3})?` with word-boundary matching
- Validation: extracted IDs are checked against the `techniques` table — only valid ATT&CK IDs are stored
- Context check: technique name appearing near the ID increases confidence
- Stored in `threat_reports.extracted_technique_ids` array and linked via `report_techniques` junction

#### IOC → Technique Linking

IOCs from ThreatFox/MalwareBazaar are linked to techniques indirectly:
1. IOC has `malware_family` (e.g., "Cobalt Strike")
2. Cross-reference against `attack_software.name` and `attack_software.aliases`
3. If match found, link IOC to all techniques used by that software (via `software_techniques`)
4. Store in `technique_iocs` with `confidence='inferred'`

OTX pulses with explicit `attack_ids` get `confidence='direct'`.

### CTI on Technique Detail Page

The technique detail page (`/techniques/:attackId`) gains a new **"Intelligence"** tab showing:

```
┌─────────────────────────────────────────────────────────┐
│ T1059.001 - PowerShell                                  │
├─────────────────────────────────────────────────────────┤
│ Overview | Procedures | Detection | Intelligence        │
├─────────────────────────────────────────────────────────┤
│                                                         │
│ Recent Reports (12)                            [View all]│
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔴 APT29 Deploys New Backdoor via Teams       3d ago│ │
│ │    Source: The DFIR Report                          │ │
│ │ 🟡 SolarMarker Campaign Targets Healthcare    1w ago│ │
│ │    Source: Unit 42                                  │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Detection Rules (8 Sigma rules)                [View all]│
│ ┌─────────────────────────────────────────────────────┐ │
│ │ 🔴 critical  Suspicious PowerShell Download String  │ │
│ │ 🟠 high      PowerShell Base64 Encoded Command      │ │
│ │ 🟡 medium    PowerShell Script Block Logging         │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Test Procedures (5 Atomic tests)               [View all]│
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Test #1: Mimikatz via PowerShell      [Windows]     │ │
│ │ Test #2: BloodHound via PowerShell    [Windows]     │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Defensive Countermeasures (3 D3FEND mappings)           │
│ ┌─────────────────────────────────────────────────────┐ │
│ │ Detect: Script Execution Analysis (D3-SEA)          │ │
│ │ Detect: Process Spawn Analysis (D3-PSA)             │ │
│ │ Isolate: Execution Isolation (D3-EI)                │ │
│ └─────────────────────────────────────────────────────┘ │
│                                                         │
│ Related IOCs (24)                              [View all]│
│ ┌─────────────────────────────────────────────────────┐ │
│ │ sha256  a1b2c3...  Cobalt Strike  ThreatFox  2d ago │ │
│ │ ip      185.x.x.x  CobaltStrike  OTX        5d ago │ │
│ └─────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### CTI Feed Status Page

A `/feed/status` page (linked in sidebar) shows ingestion health:
- Last sync time per source
- Record counts per source
- Error count / last error
- Manual "Sync Now" button per source (triggers Vercel Cron job)

### CTI Environment Variables

```
OTX_API_KEY=<your-otx-key>                    # AlienVault OTX
ABUSE_CH_AUTH_KEY=<your-abuse-ch-key>          # ThreatFox + MalwareBazaar
MALPEDIA_API_TOKEN=<your-malpedia-token>       # Malpedia (optional Tier 2)
```

Stored in Vercel environment variables, never in code or `.env` files committed to git.

### CTI Caching

- Feed list endpoints: `Cache-Control: public, s-maxage=300, stale-while-revalidate=60` (5 min)
- Technique intelligence endpoint: `Cache-Control: public, s-maxage=600, stale-while-revalidate=60` (10 min)
- Feed status: `Cache-Control: no-cache` (always fresh)

### CTI Rate Limiting

- Feed endpoints inherit global rate limiting (300 req/min per IP)
- Ingestion jobs are server-side only — no user-facing rate limit concern
- Upstream API rate limits respected:
  - OTX: 10,000 req/day (free tier)
  - abuse.ch: 300 req/min
  - CISA KEV: no limit (static file)
  - D3FEND: no limit (public API)

## Notes

- **Connection pooling**: `@vercel/postgres` uses Neon's HTTP-based serverless driver which handles connection pooling automatically — no cold-start connection storms.
- **Sectors are application-derived**, not STIX entities. They have no `stix_id` or external reference — populated by keyword extraction from group descriptions. Auto-tagged sectors include `matched_keywords` for auditability.
- **Phase 2 seeding**: Current `TRUNCATE`-based seed approach is fine for Phase 1 (read-only). Phase 2 will need `UPSERT`-based seeding to preserve user-created data (threat mappings, annotations).
- **Multi-matrix support**: `domain` column on all entities supports future ingestion of Mobile (`mobile-attack.json`) and ICS (`ics-attack.json`) matrices. Phase 1 seeds Enterprise only.
- **Re-seed automation**: Manual trigger only for Phase 1. Can add GitHub Action in future to auto-detect ATT&CK version releases.
- **Description rendering**: All entity descriptions are sanitized with DOMPurify before rendering. D3 graph uses `textContent` only, never `innerHTML`.
- **Revoked/deprecated entities**: Filtered out by default in list views. Togglable via `include_deprecated` param. Detail pages for revoked entities show a warning badge and link to the replacing entity.
