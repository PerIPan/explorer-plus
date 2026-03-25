# MITRE ICS & Mobile Domain Support — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add ICS and Mobile ATT&CK domains as selectable options via a nav bar dropdown, seeding their techniques/tactics/groups/software and filtering the entire app by selected domain.

**Architecture:** A `DomainContext` (mirroring `SectorContext`) provides the active domain to all pages. The seed script downloads all 3 STIX bundles. Every API endpoint that queries domain-aware tables adds a `WHERE domain = $N` clause. The Matrix, technique lists, and tactic lists show domain-specific data. Groups/software that span domains show cross-domain badges.

**Tech Stack:** React Context, react-router URL params (`?domain=`), Python STIX parser (existing seed.py), PostgreSQL domain column (already exists on all entity tables).

---

## Phase 1: Seed Script — Multi-Domain STIX Ingestion

### Task 1: Update seed.py to download all 3 STIX bundles

**Files:**
- Modify: `seed/seed.py`
- Modify: `seed/extract.py`

- [ ] **Step 1: Add ICS and Mobile STIX URLs to seed.py**

In `seed.py`, add URLs for all 3 domains:
```python
STIX_URLS = {
    'enterprise-attack': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json',
    'ics-attack': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json',
    'mobile-attack': 'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json',
}
```

Modify the download + parse loop to iterate over all 3 domains, passing the domain key to extract.py functions.

- [ ] **Step 2: Update extract.py to accept domain parameter**

Currently hardcodes `'domain': 'enterprise-attack'` in every extractor (lines 217, 245, 264, 291, 309, 330, 348, 368). Change each to accept and use the domain parameter passed from seed.py.

- [ ] **Step 3: Handle cross-domain deduplication**

Groups like APT28 appear in both Enterprise and ICS STIX bundles. The seed must handle this:
- `threat_groups` table has UNIQUE on `stix_id` — use `ON CONFLICT (stix_id) DO UPDATE SET domain = array_append(domain, $new_domain)` or keep the first domain and add a `domains` array column.
- **Simplest approach:** Keep `domain` as the PRIMARY domain (first seen), add a `domains TEXT[]` column for all domains an entity appears in.

- [ ] **Step 4: Add domain indexes to schema.sql**

```sql
CREATE INDEX IF NOT EXISTS idx_techniques_domain ON techniques(domain);
CREATE INDEX IF NOT EXISTS idx_tactics_domain ON tactics(domain);
CREATE INDEX IF NOT EXISTS idx_groups_domain ON threat_groups(domain);
CREATE INDEX IF NOT EXISTS idx_software_domain ON attack_software(domain);
CREATE INDEX IF NOT EXISTS idx_mitigations_domain ON mitigations(domain);
```

- [ ] **Step 5: Run seed locally with all 3 domains and verify counts**

```bash
python seed/seed.py --update
```

Expected counts (approximate):
- Enterprise: ~835 techniques, 14 tactics
- ICS: ~80 techniques, 12 tactics
- Mobile: ~120 techniques, 14 tactics

- [ ] **Step 6: Commit**

```bash
git add seed/seed.py seed/extract.py seed/schema.sql
git commit -m "feat: multi-domain STIX seeding (enterprise, ics, mobile)"
```

---

## Phase 2: Domain Context & Dropdown UI

### Task 2: Create DomainContext (mirror SectorContext)

**Files:**
- Create: `src/contexts/DomainContext.tsx`

- [ ] **Step 1: Create DomainContext**

```typescript
import { createContext, useContext, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

const STORAGE_KEY = 'mitre-domain';
const DEFAULT_DOMAIN = 'enterprise-attack';

const DOMAINS = [
  { value: 'enterprise-attack', label: 'Enterprise', short: 'Enterprise' },
  { value: 'mobile-attack', label: 'Mobile', short: 'Mobile' },
  { value: 'ics-attack', label: 'ICS', short: 'ICS' },
] as const;

type DomainValue = typeof DOMAINS[number]['value'];

interface DomainContextValue {
  domain: DomainValue;
  setDomain: (d: DomainValue) => void;
  domainParam: Record<string, string>;
  domains: typeof DOMAINS;
}

const DomainContext = createContext<DomainContextValue | null>(null);

export function DomainProvider({ children }: { children: React.ReactNode }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const urlDomain = searchParams.get('domain') as DomainValue | null;
  const [storedDomain] = useState<string | null>(
    () => sessionStorage.getItem(STORAGE_KEY)
  );

  const domain: DomainValue = urlDomain ?? (storedDomain as DomainValue) ?? DEFAULT_DOMAIN;

  function setDomain(d: DomainValue) {
    sessionStorage.setItem(STORAGE_KEY, d);
    setSearchParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set('domain', d);
      return next;
    });
  }

  const domainParam = { domain };

  return (
    <DomainContext.Provider value={{ domain, setDomain, domainParam, domains: DOMAINS }}>
      {children}
    </DomainContext.Provider>
  );
}

export function useDomain() {
  const ctx = useContext(DomainContext);
  if (!ctx) throw new Error('useDomain must be used within DomainProvider');
  return ctx;
}
```

- [ ] **Step 2: Commit**

```bash
git add src/contexts/DomainContext.tsx
git commit -m "feat: DomainContext for domain switching"
```

### Task 3: Create DomainDropdown component

**Files:**
- Create: `src/components/layout/DomainDropdown.tsx`

- [ ] **Step 1: Create DomainDropdown (mirror SectorDropdown pattern)**

Hardcoded 3 options (no API call needed). Shows a `<select>` with shield icon. Highlighted teal when not default. No clear button since a domain is always selected.

- [ ] **Step 2: Commit**

### Task 4: Wire DomainProvider + DomainDropdown into App.tsx

**Files:**
- Modify: `src/App.tsx`

- [ ] **Step 1: Wrap Layout in DomainProvider (inside SectorProvider)**

- [ ] **Step 2: Add DomainDropdown to header, right after SectorDropdown**

- [ ] **Step 3: Commit**

---

## Phase 3: API Domain Filtering

### Task 5: Add domain filter to all list API endpoints

**Files:**
- Modify: `api/v1/techniques/index.ts` — add `domain` to querySchema, add WHERE clause
- Modify: `api/v1/groups/index.ts` — add domain filter
- Modify: `api/v1/software/index.ts` — add domain filter
- Modify: `api/v1/mitigations/index.ts` — add domain filter
- Modify: `api/v1/campaigns/index.ts` — add domain filter
- Modify: `api/v1/tactics/index.ts` — add domain filter
- Modify: `api/v1/data-sources/index.ts` — add domain filter
- Verify: `api/v1/matrix.ts` — already has domain filter (confirmed)

For each endpoint:

- [ ] **Step 1: Add domain to querySchema**

```typescript
domain: z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional(),
```

- [ ] **Step 2: Add WHERE clause when domain is provided**

```typescript
if (domain) {
  params.push(domain);
  conditions.push(`t.domain = $${params.length}`);
}
```

- [ ] **Step 3: Commit**

### Task 6: Add domain filter to detail API endpoints

**Files:**
- Modify: `api/v1/techniques/[attackId].ts` — technique detail should still work across domains (same T-id can exist in multiple domains, but ICS uses different IDs like T0800+)
- Modify: `api/v1/dashboard.ts` — dashboard stats should reflect selected domain
- Modify: `api/v1/search.ts` — search results should filter by domain
- Modify: `api/v1/entities.ts` — entity search autocomplete should filter by domain

- [ ] **Step 1-4: Add domain param to each, filter accordingly**

- [ ] **Step 5: Commit**

---

## Phase 4: Frontend Domain Integration

### Task 7: Pass domain param from all pages to API hooks

**Files:**
- Modify: `src/pages/Matrix.tsx`
- Modify: `src/pages/TechniquesList.tsx`
- Modify: `src/pages/GroupsList.tsx`
- Modify: `src/pages/SoftwareList.tsx`
- Modify: `src/pages/MitigationsList.tsx`
- Modify: `src/pages/CampaignsList.tsx`
- Modify: `src/pages/DataSourcesList.tsx`
- Modify: `src/pages/TacticsList.tsx`
- Modify: `src/pages/Dashboard.tsx`

For each page:

- [ ] **Step 1: Import `useDomain` hook**

```typescript
const { domainParam } = useDomain();
```

- [ ] **Step 2: Spread domainParam into API call params**

```typescript
const params = { limit: '5000', ...sectorParam, ...domainParam };
```

- [ ] **Step 3: Verify page renders correctly with Enterprise selected**

- [ ] **Step 4: Commit**

### Task 8: Update SearchBar and entity autocomplete

**Files:**
- Modify: `src/components/layout/SearchBar.tsx`
- Modify: `src/hooks/useApi.ts` (useEntities hook)

- [ ] **Step 1: Pass domain to entities hook so autocomplete shows domain-relevant results**

- [ ] **Step 2: Commit**

### Task 9: Update Data Model graph

**Files:**
- Modify: `src/components/relationships/RelationshipModel.tsx`

- [ ] **Step 1: Add ICS and Mobile as nodes in the model graph**

New nodes:
```typescript
{ id: 'ics', label: 'ICS', x: ..., y: ..., scale: 0.85, path: '/matrix?domain=ics-attack' },
{ id: 'mobile', label: 'Mobile', x: ..., y: ..., scale: 0.85, path: '/matrix?domain=mobile-attack' },
```

New edges:
```typescript
{ from: 'ics', to: 'technique', label: 'contains', style: 'dashed' },
{ from: 'mobile', to: 'technique', label: 'contains', style: 'dashed' },
```

- [ ] **Step 2: Commit**

---

## Phase 5: Seed Production & Verify

### Task 10: Run multi-domain seed on production (Neon)

- [ ] **Step 1: Run seed script against Neon production DB**

```bash
DATABASE_URL="postgresql://..." python seed/seed.py --update
```

- [ ] **Step 2: Verify domain counts**

```sql
SELECT domain, COUNT(*) FROM techniques GROUP BY domain;
SELECT domain, COUNT(*) FROM tactics GROUP BY domain;
```

- [ ] **Step 3: Test domain switching on production**

- [ ] **Step 4: Commit any final tweaks**

---

## Unresolved Questions

- Groups span domains — show all groups regardless of domain, or filter? (recommend: show all, badge with domain)
- ICS platforms list different from Enterprise — update platformSchema?
- Dashboard stats: per-domain or global with domain breakdown?
- Sub-technique triangle on Matrix: ICS has fewer sub-techniques — any visual change?
- Sector filter + domain filter together: AND or independent?
