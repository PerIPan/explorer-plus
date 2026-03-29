# MITRE ATLAS Integration Plan

## Goal
Add ATLAS as a 4th domain (Enterprise, ICS, Mobile, **ATLAS**) in the domain selector.
Full matrix, technique 360 views, mitigations, and cross-references to ATT&CK.

## Data Source
**[mitre-atlas/atlas-data](https://github.com/mitre-atlas/atlas-data)** — ATLAS.yaml (v5.4.0)
- 16 tactics (14 map to ATT&CK, 2 AI-specific)
- 155 techniques (including sub-techniques)
- 35 mitigations with 246 technique links
- 34 ATT&CK cross-references

## Real Numbers (from investigation)
- 247 AI/ML CVEs already in our cve_details
- 22 AI applications already in our applications table
- 11 ATLAS-linked ATT&CK techniques already have app/CVE data
- Chain: ATLAS technique → ATT&CK xref → CVE → Application → Threat Group

---

## Phase 0: Foundational Fixes (before ATLAS)

### 0.1 Shared domain enum
- Extract `VALID_DOMAINS` constant: `['enterprise-attack', 'mobile-attack', 'ics-attack', 'atlas-attack']`
- Update all 13 API handlers to import it instead of hardcoding

### 0.2 attackIdSchema regex
- Update to: `/^(AML\.)?(TA|T|G|S|M|C|DS)\d{4}(\.\d{3})?$/`
- Handles both ATT&CK (`T1059.001`) and ATLAS (`AML.T0051`)

### 0.3 getParentId() utility
- Replace all 11 `.split('.')[0]` call sites
- Logic: `id.replace(/\.\d{3}$/, '')` — strips only the 3-digit sub-technique suffix
- `AML.T0051` → `AML.T0051` (correct), `AML.T0051.001` → `AML.T0051` (correct)

### 0.4 Add maturity column
- `ALTER TABLE techniques ADD COLUMN maturity VARCHAR(20)` — nullable, only ATLAS uses it

### 0.5 DOMAIN_SHORT map
- Add `'atlas-attack': 'ATLAS'` to SearchBar

### 0.6 Reseed safety
- Change seed truncate to `DELETE FROM techniques WHERE domain != 'atlas-attack'` (preserve ATLAS on ATT&CK reseed)

---

## Phase 1: Schema + Data Ingestion

### 1.1 Approach: Reuse Existing Tables

ATLAS data fits existing tables with `domain = 'atlas'`:

```sql
-- techniques table — already has domain column
INSERT INTO techniques (attack_id, name, description, domain, is_subtechnique, ...)
VALUES ('AML.T0051', 'LLM Prompt Injection', '...', 'atlas', false, ...);

-- tactics table — already has domain column
INSERT INTO tactics (attack_id, name, description, domain, sort_order, ...)
VALUES ('AML.TA0000', 'AI Model Access', '...', 'atlas', 4, ...);

-- mitigations table — already has domain column
INSERT INTO mitigations (attack_id, name, description, domain, ...)
VALUES ('AML.M0000', 'Limit Public Release of Information', '...', 'atlas', ...);

-- technique_tactics — existing junction
-- mitigation_techniques — existing junction
```

### 1.2 New Table: Cross-references

```sql
CREATE TABLE IF NOT EXISTS atlas_xrefs (
  atlas_attack_id   VARCHAR(20) NOT NULL,  -- AML.T0051
  attack_technique_id VARCHAR(20) NOT NULL, -- T1059
  atlas_technique_id UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id_fk UUID REFERENCES techniques(id) ON DELETE CASCADE,
  PRIMARY KEY (atlas_attack_id, attack_technique_id)
);
CREATE INDEX idx_atlas_xrefs_attack ON atlas_xrefs(attack_technique_id);
```

### 1.3 Ingestion Script: `scripts/sync-atlas.mjs`

- Download ATLAS.yaml from GitHub
- Parse with js-yaml
- Upsert tactics with `domain = 'atlas'`
- Upsert techniques with `domain = 'atlas'`, parent_technique_id for subs
- Upsert mitigations with `domain = 'atlas'`
- Insert technique_tactics junction rows
- Insert mitigation_techniques junction rows
- Insert atlas_xrefs for the 34 ATT&CK cross-references
- Resolve technique UUIDs for FK links

### 1.4 Domain Selector Update

```ts
// DomainContext.tsx — add atlas
const DOMAINS: DomainOption[] = [
  { value: 'enterprise-attack', label: 'Enterprise', short: 'Enterprise' },
  { value: 'mobile-attack',     label: 'Mobile',     short: 'Mobile' },
  { value: 'ics-attack',        label: 'ICS',        short: 'ICS' },
  { value: 'atlas',             label: 'ATLAS',      short: 'ATLAS' },
  { value: 'all',               label: 'All Domains', short: 'All' },
];
```

### 1.5 Entities API

- Already filters by domain — ATLAS techniques auto-appear when `domain=atlas`
- Search returns ATLAS techniques alongside ATT&CK when `domain=all`

---

## Phase 2: Matrix View

### 2.1 Matrix Rendering
- Existing `MatrixGrid` works with any domain — it renders tactics as columns, techniques as cells
- ATLAS matrix: 16 columns (tactics), ~60 parent techniques
- The 2 AI-specific tactics (AI Model Access, AI Attack Staging) appear as new columns
- No code changes needed if the matrix API returns ATLAS data when `domain=atlas`

### 2.2 Matrix API
- Existing `/matrix` endpoint already filters by domain
- Need to verify it handles `domain=atlas` correctly
- May need to add `atlas` to the domain validation enum

---

## Phase 3: Technique 360 Views

### 3.1 ATLAS Technique Detail
- Existing TechniqueDetail page works — it queries by `attack_id` + domain
- ATLAS techniques show: description, tactics, mitigations, maturity level
- New field: **ATT&CK Equivalent** — link to the cross-referenced ATT&CK technique
- New field: **Maturity** badge (realized / demonstrated / feasible)

### 3.2 ATT&CK Technique Enhancement
- For the 34 ATT&CK techniques with ATLAS equivalents, show:
  - "ATLAS AI Context" section in the technique 360 view
  - Link to the ATLAS technique
  - ATLAS mitigations for AI-specific defense

### 3.3 TechniqueMapView
- Show ATLAS mitigations alongside ATT&CK mitigations
- Show ATT&CK cross-reference link

---

## Phase 4: Cross-Domain Integration

### 4.1 Application → ATLAS Chain
- 22 AI applications already exist
- Via ATT&CK xref: Application → CVE → technique → ATLAS technique
- Show in ApplicationMapView: "ATLAS Techniques" section

### 4.2 ATLAS in Search
- Search "prompt injection" → finds AML.T0051
- Search "T1059" → shows both ATT&CK T1059 AND linked AML.T0050

### 4.3 Data Model Diagram
- Add ATLAS node to RelationshipModel
- Connect to Technique (cross-references)
- Category: 'core' (same as other domains)

### 4.4 Feed Status
- Add ATLAS card (synced/pending)

---

## Phase 5: Ongoing Sync

### 5.1 Monthly Vercel Cron
- ATLAS updates infrequently (~quarterly)
- Monthly cron: `0 5 15 * *` (15th of each month)
- Re-download ATLAS.yaml, upsert all data

### 5.2 Version Tracking
- Store ATLAS version in feed_sync_log
- Only re-sync if version changed

---

## Volume Estimates

| Table | New Rows | Impact |
|-------|----------|--------|
| tactics | +16 | negligible |
| techniques | +155 | negligible |
| mitigations | +35 | negligible |
| technique_tactics | +155 | negligible |
| mitigation_techniques | +246 | negligible |
| atlas_xrefs | +34 | negligible |
| **Total** | **~641 rows** | **< 1 MB** |

ATLAS is tiny — no storage concerns.

---

## Risk / Notes

- `attack_id` column is `VARCHAR(20)` — ATLAS IDs like `AML.T0051` fit (11 chars)
- Domain validation enums in API handlers need `atlas` added
- Matrix sort_order for ATLAS tactics needs custom ordering
- The 2 AI-specific tactics have no ATT&CK tactic equivalent — they just appear as extra columns
- ATLAS has NO groups/campaigns/software — those sections show empty (or via ATT&CK xref chain)
- Maturity field (realized/demonstrated/feasible) is ATLAS-specific — display as badge

---

## Decisions (Resolved)

- **domain value**: `atlas-attack` (matches enterprise-attack pattern)
- **matrix**: same matrix page with domain filter
- **maturity badges**: realized=green, demonstrated=yellow, feasible=orange + tooltip explaining each
- **cross-refs**: two-way links (ATLAS → ATT&CK and ATT&CK → ATLAS)
- **ATLAS mitigations**: visible in ATT&CK mitigation pages (domain=all shows both)
