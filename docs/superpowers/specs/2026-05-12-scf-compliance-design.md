# SCF Compliance Integration — Design

> Bridge MITRE ATT&CK with the Secure Controls Framework's catalogue of ~250 compliance and regulatory frameworks. Add a "compliance lens" across every existing entity (techniques, tactics, threat groups, malware, sectors) and a new top-level Compliance section.

**Author:** 2026-05-12 (v1) · 2026-05-12 (v2 — architect-reviewer + postgres-pro feedback) · 2026-05-12 (v3 — domain-stratified rollout: Enterprise now, ATLAS/ICS/Mobile staged)

---

## Coverage by domain (v3 reframe)

Current SCF 2026.1.1 (May 2026) maps to **ATT&CK v16**. Our DB is on **v19**. Measured 2026-05-12:

| Domain | Total techniques | SCF mapped | Coverage |
|---|---:|---:|---:|
| **enterprise-attack** | 697 | **495** | **71%** ← launch-ready |
| atlas-attack (AI/ML) | 155 | 0 | 0% — SCF doesn't cover AI |
| mobile-attack | 124 | 1 | <1% — SCF doesn't cover Mobile |
| ics-attack | 97 | 0 | 0% — SCF's ICS mappings live in IEC 62443 / NERC CIP / NIST 800-82 columns, mapped only to Enterprise techniques |

**Top-100 most-used Enterprise techniques: 70% SCF coverage.** That's the lens that matters for everyday analyst/GRC use.

**Why ATLAS / Mobile / ICS are 0% in SCF:** these domains have their own compliance ecosystems, not SCF's purview.

| Domain | Native compliance regimes (Phase 9–11 data sources) |
|---|---|
| **ATLAS (AI/ML)** | EU AI Act · NIST AI RMF · OWASP AI Exchange · ISO 42001 |
| **Mobile** | OWASP MASVS · NIST 800-124 · MDM standards |
| **ICS** | IEC 62443-2-1/3-3/4-2 · NERC CIP · NIST 800-82 (SCF has these columns but mapped only to Enterprise techniques — Phase 10 re-uses the data via different cross-walk) |

**Decision (v3): domain-stratified rollout.** Ship Enterprise lens now (Phases 0–8). ATLAS / Mobile / ICS get domain-specific lenses in Phases 9–11 using regime-appropriate data we either already have or can fetch separately. SCF version-skew is a 3% (15/511) gap on Enterprise — covered by `is_unresolved` defense-in-depth.

---

## Why

We already cover MITRE ATT&CK, ATLAS, CVEs, GHSA/OSV advisories, and a dozen ATT&CK-adjacent frameworks (OWASP, NIST 800-53, NIST CSF v2, CAPEC, Engage, RE&CT, VERIS, Cloud Controls, Sigma, Atomic). What we don't have is the **regulatory / audit lens** — the answer to "if my org is bound by NIS2 / DORA / PCI / HIPAA / CRA, which ATT&CK techniques do I owe coverage on?"

SCF (Secure Controls Framework) is a maintained CC BY 4.0 catalogue that maps **1,469 controls** to **~250 frameworks**, including a dedicated MITRE ATT&CK column. That's the rosetta stone we need.

This integration adds:
1. A new top-level `/compliance` section
2. SCF-backed framework detail pages (DORA, NIS2, PCI DSS, etc.)
3. Compliance enrichment panels on every existing entity that benefits

Outcome: the product becomes a **threat-driven ⇄ compliance-driven bridge**. CISOs presenting to boards can finally say "we're protecting against APT28 *and* satisfying DORA Article 9 with the same controls."

---

## Out of scope

- **Full upstream framework text.** SCF gives us IDs and cross-references; the actual control text in PCI DSS, ISO 27002, IEC 62443, etc. lives in copyrighted upstream documents. We link out, never republish.
- **CIS Controls 8.1.** Licensed CC BY-NC-SA; safe to display SCF's IDs as cross-refs, but no enrichment beyond that. (Mirrors the existing deferred-ingest memory.)
- **STRM PDFs.** SCF publishes separate per-framework PDFs (e.g. `scf-strm-emea-eu-cyber-resilience-act-2022.pdf`). Not parsed. The XLSX has 250+ frameworks already; PDFs add marginal new content for high effort.
- **ATLAS sync.** `scripts/sync-atlas.mjs` continues to own the ATLAS data flow.
- **Tier-3 framework UX.** All ~250 SCF-tracked frameworks are ingested into the DB. The default UI surfaces the curated Tier 1 (12 global) + Tier 2 (10 regional/sectoral) = **22 featured**. Tier 3 (the 200+ long tail) is reachable only via a "Show all" toggle.

---

## Decisions

| # | Decision | Choice | Rationale |
|---|---|---|---|
| 1 | Sidebar placement (v3) | **New `Compliance` section** with 4 nested entries, one per ATT&CK domain. Existing CRA + OWASP AI stay in Frameworks (no migration). | Per-domain entries make the scope of compliance coverage visible at a glance + leave room for the staged ATLAS/Mobile/ICS rollouts. |
| 2 | Default framework set | **22 curated** (Tier 1 + Tier 2). All 250+ ingested but hidden behind toggle. | Cards/rows for 250 = unusable. Curated = scannable in one screen. |
| 3 | Page primitive | **Rows, not cards** | Matches our Feed Status / Ecosystems Table pattern. 22 rows fit one viewport. |
| 4 | Default view on framework detail page | **Article-first** (Compliance → ATT&CK), with toggle for technique-first | Angle B = the GRC magnet. Analyst inverse is one click. |
| 5 | Coverage metric on framework rows | **Filtered count** (techniques with ≥2 SCF controls mapping) + raw count visible on hover | Honest signal of depth, not "everything is in scope via Continuous Monitoring." Inline tooltip explaining the filter (not hover-only). |
| 6 | Identifier convention | **UPSERT by `scf_id`** (e.g. CFG-02). SCF IDs are stable across releases. | Same pattern as ATT&CK stix_id — DB UUIDs preserved across releases. |
| 7 | Ingest cadence | **Manual workflow_dispatch** | SCF ships quarterly. Human review gate before content rotation, same model as `update-attack.mjs`. |
| 8 | Cross-domain "Software" naming | Code/routes stay `software`; **UI labels say `Malware`** | Repository-wide convention established 2026-04-27 (commit 71976fb). |
| 9 | License posture | Add SCF to `/about/attributions` (CC BY 4.0 — attribution required). **Global footer credit** — not just `/compliance/*` — because SCF data permeates entity pages. | Compliance with CC BY. |
| 10 | Out-of-band frameworks | `/compliance` hub *also* surfaces our existing dedicated pages (CRA, OWASP AI, NIST 800-53, NIST CSF v2, OWASP Top 10) as cross-links in an "Also on this site" block | Maintains discoverability without duplicating rich pages. |
| 11 | **ATT&CK ID drift handling** (v2) | Add `is_unresolved BOOLEAN` flag on `scf_attack_mappings` + `last_validated_attack_version` on `scf_controls`. Persist unresolved IDs but filter them from counts; show amber badge on affected entity panels. | Critical: SCF lags ATT&CK by ~1 release. Without this the compliance shadow silently undercounts after every ATT&CK release. |
| 12 | **Roll-up perf** (v2) | Pre-compute `scf_group_compliance_summary` + `scf_software_compliance_summary` + `scf_sector_compliance_summary` at end of ingest. Entity pages do a 22-row lookup, not a 5-table join. | Drops p95 from ~150ms to <10ms on Neon's shared-compute tier. |
| 13 | **Atomic ingest** (v2) | Shadow-table swap for `scf_framework_refs` + the three summary tables. Build into `*_new`, then atomic RENAME at end of ingest. | Eliminates partial-state reads + UPSERT overhead on 200K-row table. |
| 14 | **Framework key stability** (v2) | `scf_framework_aliases(framework_key, source_header)` table. Ingester populates from observed column headers. Fail loud only when a Tier-1 key loses all aliases. | SCF reshuffles column headers between releases. Stable URLs (`/compliance/eu-nis2`) must survive header churn. |

---

## Architecture

### Tables (new — v2)

```sql
-- 1. SCF control catalogue (~1500 rows)
CREATE TABLE scf_controls (
  scf_id                         TEXT PRIMARY KEY,          -- e.g. 'CFG-02'
  domain                         TEXT NOT NULL,             -- e.g. 'Configuration Management'
  name                           TEXT NOT NULL,
  description                    TEXT NOT NULL,             -- 'Mechanisms exist to...'
  threat_codes                   TEXT[],                    -- ['MT-1','MT-7','NT-7']
  risk_codes                     TEXT[],                    -- ['R-AC-1','R-EX-2',…]
  last_validated_attack_version  TEXT,                      -- 'v16' / 'v19' — what SCF release's ATT&CK column we ingested
  unresolved_attack_count        INT NOT NULL DEFAULT 0,    -- attack_ids referenced but not in current `techniques` table
  created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. SCF control → ATT&CK technique (M:N, ~30K rows).
--    is_unresolved=true means SCF lists this attack_id but it doesn't exist in our
--    current `techniques` table (renamed/revoked in newer ATT&CK release).
--    All roll-up queries MUST filter `AND NOT is_unresolved` for accurate counts.
CREATE TABLE scf_attack_mappings (
  scf_id            TEXT NOT NULL REFERENCES scf_controls(scf_id) ON DELETE CASCADE,
  attack_id         VARCHAR(20) NOT NULL,      -- matches techniques.attack_id type (v2 fix — was TEXT)
  is_unresolved     BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (scf_id, attack_id)
);
-- Covering index — joins use attack_id, then immediately need scf_id
CREATE INDEX idx_scf_attack_mappings_attack_covering
  ON scf_attack_mappings(attack_id) INCLUDE (scf_id);
CREATE INDEX idx_scf_attack_mappings_unresolved
  ON scf_attack_mappings(attack_id) WHERE is_unresolved;

-- 3. SCF control → other framework refs (~150-200K rows).
--    No CASCADE here — scf_framework_refs is pure derived data,
--    rebuilt via shadow-table swap each ingest (v2 — was UPSERT).
CREATE TABLE scf_framework_refs (
  scf_id            TEXT NOT NULL,
  framework_key     TEXT NOT NULL,             -- 'pci-dss-4', 'eu-nis2', 'iso-27002-2022'
  ref_id            TEXT NOT NULL,             -- '2.2.1', 'Article 9.3(a)', '8.3'
  PRIMARY KEY (scf_id, framework_key, ref_id)
);
CREATE INDEX idx_scf_framework_refs_fw      ON scf_framework_refs(framework_key);
CREATE INDEX idx_scf_framework_refs_scf_fw  ON scf_framework_refs(scf_id, framework_key);

-- 4. Framework catalogue (~255 rows from SCF Authoritative Sources sheet)
CREATE TABLE scf_frameworks (
  framework_key     TEXT PRIMARY KEY,
  name              TEXT NOT NULL,
  version           TEXT,
  source_org        TEXT NOT NULL,
  upstream_url      TEXT NOT NULL,
  region            TEXT NOT NULL,             -- 'global' | 'eu' | 'us' | 'uk' | 'apac' | 'mena' | 'americas'
  tier              INT  NOT NULL DEFAULT 3,   -- 1, 2, or 3
  license           TEXT,
  short_blurb       TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_scf_frameworks_tier ON scf_frameworks(tier);

-- 5. Alias table — v2. Decouples /compliance/<framework_key> URLs from
--    the volatile SCF column headers (e.g. 'EU NIS2' → 'EU NIS 2 Directive'
--    between SCF releases).
CREATE TABLE scf_framework_aliases (
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  source_header     TEXT NOT NULL,             -- raw XLSX header as seen by the ingester
  first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (framework_key, source_header)
);

-- 6. Cross-framework technique overlap (~31K rows, lower-triangular).
--    Rebuilt at end of every ingest via INSERT (not trigger, not matview).
CREATE TABLE scf_framework_overlap (
  fw_a              TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  fw_b              TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  technique_overlap INT NOT NULL,
  PRIMARY KEY (fw_a, fw_b),
  CHECK (fw_a < fw_b)
);
CREATE INDEX idx_scf_framework_overlap_b ON scf_framework_overlap(fw_b);

-- 7. Pre-computed group / malware / sector compliance shadow counts (v2).
--    Built at end of ingest. Entity pages do PK lookup, not 5-table join.
CREATE TABLE scf_group_compliance_summary (
  group_id          UUID NOT NULL REFERENCES threat_groups(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (group_id, framework_key)
);
CREATE INDEX idx_scf_group_summary_group ON scf_group_compliance_summary(group_id);

CREATE TABLE scf_software_compliance_summary (
  software_id       UUID NOT NULL REFERENCES attack_software(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (software_id, framework_key)
);
CREATE INDEX idx_scf_software_summary ON scf_software_compliance_summary(software_id);

CREATE TABLE scf_sector_compliance_summary (
  sector_id         UUID NOT NULL REFERENCES sectors(id) ON DELETE CASCADE,
  framework_key     TEXT NOT NULL REFERENCES scf_frameworks(framework_key) ON DELETE CASCADE,
  controls          INTEGER NOT NULL,
  techniques_ref    INTEGER NOT NULL,
  PRIMARY KEY (sector_id, framework_key)
);

-- 8. Hand-curated tier + region + sector affinities (TypeScript, drives the seeder)
-- src/lib/scf-framework-registry.ts — 22 Tier-1+2 entries.
-- src/lib/sector-regime-affinity.ts — sectors → typical compliance regimes lookup
--   (e.g. healthcare → HIPAA, NIST 800-66, ISO 27799, NIS2)
```

**Shadow-table swap pattern** (v2). For tables marked atomic-rebuild — `scf_framework_refs` + the 3 summary tables + `scf_framework_overlap` — the ingester:

1. Creates `scf_<table>_new`, loads via plain `COPY` / `INSERT … SELECT`
2. At end of ingest:
   ```sql
   BEGIN;
     ALTER TABLE scf_framework_refs RENAME TO scf_framework_refs_old;
     ALTER TABLE scf_framework_refs_new RENAME TO scf_framework_refs;
     -- … same for summary tables …
   COMMIT;
   DROP TABLE scf_framework_refs_old;
   ```
3. `ALTER TABLE … RENAME` is near-instant (AccessExclusiveLock held microseconds). Readers see either old or new full state — never partial.

### Routes (new — v3 domain-stratified)

| Route | Page | Phase |
|---|---|---|
| `/compliance` | Meta-hub: 4 domain cards (Enterprise / ATLAS / ICS / Mobile) with coverage stats. Click a domain → its hub | 1 |
| `/compliance/enterprise` | Enterprise hub — rows of 22 featured frameworks via SCF | 1 |
| `/compliance/atlas` | ATLAS hub — wip stub until Phase 9 | 1 (stub) → 9 (live) |
| `/compliance/ics` | ICS hub — wip stub until Phase 10 | 1 (stub) → 10 (live) |
| `/compliance/mobile` | Mobile hub — wip stub until Phase 11 | 1 (stub) → 11 (live) |
| `/compliance/<framework_key>` | Per-framework detail page (Article ↔ Technique views). Flat namespace; a framework like NIS2 may appear in multiple domain hubs but lives at a single URL | 2 |

### Sidebar (v3)

```
Compliance                          ← new section header
  Enterprise          → /compliance/enterprise        live (Phase 1)
  ATLAS – wip         → /compliance/atlas             stub (live in Phase 9)
  ICS – wip           → /compliance/ics               stub (live in Phase 10)
  Mobile – wip        → /compliance/mobile            stub (live in Phase 11)
```

The "wip" badges match the existing CRA / OWASP AI pattern — users understand them. Each stub page explains what regimes it'll cover, the planned timeline, and links to upstream sources (EU AI Act on EUR-Lex, IEC 62443 storefront, OWASP MASVS, etc.) so the page has value even before its data ingest lands.

### Routes (existing — get a new panel)

| Route | New panel | Phase |
|---|---|---|
| `/cti/techniques/<id>` | "Compliance frameworks" — 22 framework chips with article/section IDs | 3 |
| `/cti/tactics/<id>` | "Compliance emphasis" — top 5 frameworks by reference count | 4 |
| `/groups/<id>` | "Compliance shadow" — roll-up across the group's technique stack | 5 |
| `/software/<id>` (UI: "Malware") | "Compliance shadow" — same logic via software's technique stack | 6 |
| `/sectors/<id>` | "Regulatory obligations" — typical sector regimes + group-coverage overlap | 7 |

### Ingester (`scripts/sync-scf.mjs`)

Lives alongside `update-attack.mjs`. Same patterns:
- `pg.Pool` with `keepAlive`
- `feed_sync_log` lifecycle (`source = 'scf'`)
- `pg_try_advisory_lock` (key `0x736366` = ASCII 'scf')
- Strictly-greater version guard (SCF release name like `2026.1.1` → compare to last successful run's metadata)
- Manual `workflow_dispatch` only — no schedule (SCF ships quarterly)

Flow:
1. Download `Secure Controls Framework (SCF) - YYYY.X.Y.xlsx` from GitHub releases
2. Parse `Authoritative Sources` sheet → UPSERT `scf_frameworks` rows. New framework names that don't have a curated entry in `scf-framework-registry.ts` get `tier=3, region='global'` (or guessed from row's `Geography` column).
3. Parse `SCF YYYY.X` main sheet (1469 controls × 369 columns):
   - For each row: UPSERT `scf_controls`
   - Walk columns: identify framework-mapping columns (header matches a regex/lookup), extract semicolon-separated ref IDs, UPSERT into `scf_framework_refs`
   - Extract the `MITRE / ATT&CK / N` column → UPSERT `scf_attack_mappings` (parse T#### tokens)
4. Per-slice atomic transaction (same pattern as `update-attack.mjs` v5).
5. Pre/post snapshot diff verifies no regression.

**Column drift handling:** quarterly SCF releases sometimes rename or reorder framework columns. Match by header substring with a curated regex lookup; fail loud if a previously-known framework column disappears entirely.

**Estimated row counts after first ingest:**
- `scf_controls`: ~1,500
- `scf_attack_mappings`: ~30,000
- `scf_framework_refs`: ~150,000–200,000
- `scf_frameworks`: ~255

Total Postgres footprint: <50 MB.

---

## Page designs

### `/compliance` hub

Row-dense list, grouped by tier sub-headers, with region + sector filter chips. Each row:

```
● <framework name + version>   <region chip>   <source org>   <coverage>   <license badge>
```

- Dot color encodes license class (green = public domain, teal = permissive, yellow = CC BY/SA, orange = commercial)
- Coverage = `<filtered_tech_count> tech · <scf_control_count> SCF`
- Hover reveals raw counts + last-published date
- Click row → `/compliance/<framework_key>`

Sections (all collapsible after the first):
1. **FEATURED · GLOBAL** (Tier 1 — 6 rows)
2. **FEATURED · EU REGULATORY** (5 rows: NIS2, DORA, AI Act, GDPR, CRA-wip cross-link)
3. **FEATURED · US REGULATORY** (5 rows: NIST 800-53, HIPAA, CMMC, FedRAMP, NIST 800-171)
4. **SECTORAL & REGIONAL · Tier 2** (10 rows — expand by default off)
5. **ALL OTHER (250+)** — expand toggle, searchable
6. **ALSO ON THIS SITE** — 6 cross-links to existing dedicated framework pages

Hub URL surfaces well for SEO terms like "NIS2 ATT&CK", "DORA cybersecurity controls", "PCI DSS technique coverage".

### `/compliance/<framework_key>` — framework detail (DORA example)

```
EU DORA · Reg. (EU) 2022/2554                              Region: EU
─────────────────────────────────────────────────────────
Effective: 17 January 2025
Scope:     EU financial entities + ICT third-party providers
Enforcer:  ESMA, EBA, EIOPA, national competent authorities

→ 184 ATT&CK techniques · 142 SCF controls · 44 articles cited
→ Read the law:  eur-lex.europa.eu/eli/reg/2022/2554/oj  ↗

[Domain ▾]  [Tactic ▾]  [Article ▾]      [View: Article ▾]

──── BY ARTICLE  (default, GRC-friendly) ──────────────
▼ Article 9 · ICT Protection and Prevention     47 techniques
   T1078 Valid Accounts             Initial Access   via 4 SCF
   T1190 Public-Facing Application  Initial Access   via 2 SCF
   ... (collapsible per article)
▼ Article 10 · Detection                        38 techniques
▼ Article 11 · Response and Recovery            29 techniques
▼ Article 14 · Incident Reporting               17 techniques
▼ Articles 23-30 · Third-Party Risk Mgmt        52 techniques
▼ Articles 32-44 · Critical TPSP Oversight      11 techniques

──── BY ATT&CK TECHNIQUE  (analyst inverse — view toggle) ──
   T1003 OS Credential Dumping   Credential Access   Articles: 9, 10
   T1059 Command/Scripting        Execution           Articles: 9, 10
   ... (sortable, paginated, links to /cti/techniques/<id>)

──── RELATED FRAMEWORKS (overlap) ─────────────────────
   ● EU NIS2          267 tech overlap     /compliance/nis2
   ● EBA / GL/2019/04 63 tech overlap      /compliance/eba-gl-2019-04
   ● ISO 27002:2022   182 tech overlap     /compliance/iso-27002-2022
   ● NIST CSF v2      159 tech overlap     /compliance/nist-csf-v2

──── SOURCES ─────────────────────────────────────────
   ↗ EUR-Lex official text
   ↗ EBA Final Report (RTS)
   ↗ ESMA Technical Standards
   ↗ Secure Controls Framework (SCF)

Disclaimer: compliance mappings indicate framework intent, not
verified technical mitigation. Combine with ATT&CK's own M#### +
detection strategies on each technique page.
```

Overlap counts (`267 tech overlap`) are pre-computed at ingest time using a CTE that intersects the two frameworks' `attack_id` sets via `scf_framework_refs`. Stored in a cached table `scf_framework_overlap(fw_a, fw_b, technique_overlap)` (~250² / 2 = ~31K rows).

### Entity-side panels

All five entity panels share a single shape:

```
COMPLIANCE FRAMEWORKS                                    [filter: Global ▾]
  ● <framework>     <ref_count> refs    via <scf_count> controls
  ● <framework>     ...
  ... (Tier 1+2 only; "Show all" expands to Tier 3)

▸ Inverse: an organization pursuing <framework> compliance addresses
  N% of <this entity>'s technique stack.
```

Roll-up SQL (group example):

```sql
SELECT f.framework_key, f.name, f.region, f.tier,
       COUNT(DISTINCT fr.scf_id) AS controls,
       COUNT(DISTINCT m.attack_id) AS techniques_referenced
FROM group_techniques gt
JOIN techniques t           ON t.id = gt.technique_id
JOIN scf_attack_mappings m  ON m.attack_id = t.attack_id
JOIN scf_framework_refs  fr ON fr.scf_id = m.scf_id
JOIN scf_frameworks      f  ON f.framework_key = fr.framework_key
WHERE gt.group_id = $1
  AND f.tier <= 2
GROUP BY f.framework_key, f.name, f.region, f.tier
ORDER BY techniques_referenced DESC;
```

Pre-materialise the heavy query as a function or a materialised view if p95 exceeds 200 ms on dashboard pages.

---

## License & attribution

SCF is **CC BY 4.0**. Compliance requirements satisfied by:

1. Adding SCF to `/about/attributions` (Tier 2 — CC BY) with the upstream URL.
2. Small footer credit on `/compliance/*` pages: *"Powered by Secure Controls Framework (SCF) — CC BY 4.0."*
3. Linking to the SCF source in the framework detail page's Sources block.

ISO and IEC standards remain copyrighted by their respective bodies — we cite IDs only and link to the official storefront. No standard text is republished.

PCI DSS, NIST, FedRAMP, US gov standards are public domain or freely usable; cite IDs and link to authoritative documents.

EU regulations are open via EUR-Lex; link there for the law text.

---

## Phase plan & effort (v2 — reordered per reviewers)

| Phase | Deliverable | Effort | Notes |
|---|---|---|---|
| 0 | `scf_*` schema migrations + `scf_framework_aliases` + ATT&CK ID classifier + `sync-scf.mjs` ingester + first run with shadow-table swap | 0.75 day | v2: schema bigger, classifier step added |
| 1 | `/compliance` hub (row-dense, region/sector filters, "show all" toggle) | 0.5 day | |
| 1.5 | **Roll-up perf budget commit** — measure 5 entity-side roll-up queries against pre-computed summary tables; codify 50ms p95 SLO | 0.25 day | v2: new — codify perf before building all 5 entity panels |
| 2 | `/compliance/<framework>` detail (Article + Technique views) **+ `scf_framework_overlap` populated at ingest** | 1 day | v2: matview pulled forward from Phase 8 |
| 3 | Technique-side panel on `/cti/techniques/<id>` | 0.5 day | |
| 4 | Tactic emphasis roll-up on `/cti/tactics/<id>` | 0.25 day | |
| 5 | Threat-group compliance shadow on `/groups/<id>` (reads `scf_group_compliance_summary`) | 0.25 day | v2: dropped from 0.5d — query is now a PK lookup |
| 6 | Malware compliance shadow on `/software/<id>` (UI: "Malware", reads `scf_software_compliance_summary`) | 0.25 day | |
| 7 | Sector regulatory obligations + group-coverage cross-reference on `/sectors/<id>` (reads `scf_sector_compliance_summary` + `sector-regime-affinity.ts`) | 0.5 day | Hand-curated sector→regime lookup |
| 8 | Sidebar entry, sitemap, structured-data JSON-LD, attribution updates (global footer) | 0.25 day | v2: lighter — overlap matview moved to Phase 2 |
| 8.5 | **Observability** — orphan-mapping count in `/feed-status`, framework_key alias drift detection, slow-query alerting, per-Tier-1 framework_key disappearance pager | 0.5 day | v2: new — covers postgres/architect drift concerns |
| **9** | **ATLAS compliance lens** — `/compliance/atlas` populated. Reuses existing data we already have: OWASP AI Exchange page, ATLAS xrefs table, NIST AI RMF, EU AI Act stub. New table `atlas_compliance_refs` maps ATLAS techniques → AI-regime articles. Same row-dense layout, same entity-side roll-up panels for ATLAS techniques. | 1 day | v3: new |
| **10** | **ICS compliance lens** — `/compliance/ics` populated. Re-uses SCF data (IEC 62443-2-1/3-3/4-2, NERC CIP columns already in `scf_framework_refs`) but cross-walks via OT-specific authoritative-source curation. Adds NIST 800-82 r3 references. | 1 day | v3: new — no new ingester, different presentation of existing SCF rows |
| **11** | **Mobile compliance lens** — `/compliance/mobile` populated. Pulls OWASP MASVS (CC BY-SA, fetchable) + NIST 800-124 r2 (public domain). Smaller catalog (~50 controls vs SCF's 1469). | 0.5 day | v3: new — smaller surface |

**Totals (v3):**
- **Enterprise MVP (Phases 0–3):** ~2.75 days
- **Enterprise full (Phases 0–8.5):** ~5.0 days
- **Multi-domain (Phases 0–11):** ~7.5 days

Domain-stratified means each subsequent phase ships value to a new audience segment without rework of earlier phases.

**Phase ordering rationale (v2):**
- **Overlap precomp moved earlier** (Phase 8 → Phase 2) — `/compliance/<framework>` shows "Related Frameworks (overlap)" so the table that powers it must exist before that page ships
- **Perf budget at 1.5** — codifies the SLO before all 5 entity-side panels get built. Avoids retrofitting performance into Phases 5–7
- **Observability at 8.5** — orphan-mapping count visibility, framework_key alias-drift detection, slow-query alerts. Without this the integration silently rots over multiple SCF releases.

---

## Validation gates (v2)

| Gate | Pass criterion |
|---|---|
| Ingest correctness | Random sample of 10 SCF controls → cross-check ref IDs against the raw XLSX |
| ATT&CK mapping coverage | Every SCF control with a non-empty ATT&CK column has at least one row in `scf_attack_mappings` |
| **ATT&CK drift classifier (v2)** | Run produces non-zero `unresolved_attack_count` total written to `feed_sync_log.metadata.unresolvedTotal`. Expected ~15 on first run against v19 |
| **Shadow-table swap (v2)** | `scf_framework_refs_old` exists immediately post-swap and is dropped by end of run; readers during the swap window get either old or new full state, never partial |
| Framework registry | Every framework with ≥10 SCF controls referencing it has a `framework_key` + `region` + `tier` in `scf-framework-registry.ts`. Tier-1 keys must have ≥1 alias in `scf_framework_aliases` |
| Hub render | `/compliance` returns 200 + lists 22 featured frameworks |
| Detail page render | `/compliance/eu-dora` shows article-grouped technique list + works toggle to technique view |
| Technique panel | `/cti/techniques/T1059` shows ≥10 framework chips, with "v19-revoked" badge on any reference to revoked techniques |
| Group shadow | `/groups/G0007` shows ≥10 framework rows, latency p95 < 50ms (PK lookup against summary table) |
| Sector roll-up | `/sectors/healthcare` shows HIPAA + NIST 800-66 + ISO 27799 + NIS2 with correct overlap counts |
| Attributions | SCF entry present on `/about/attributions` under "CC BY" tier with upstream URL. Global footer credit visible on every page that displays SCF data |
| **Observability (v2)** | `/feed-status` row for `scf` shows last `unresolvedTotal` + last `aliasDriftCount`. Workflow run fails if a Tier-1 `framework_key` loses all aliases |

---

## Open follow-ups (post-MVP)

- **Gap analysis** — pick N frameworks, show ATT&CK techniques NOT covered by any of them. "Your auditor will never catch this" view.
- **Maturity tier overlay** — SCF has SCR-CMM levels (0-5) per control. Could power a maturity-progression view on the framework detail page.
- **STRM PDF ingest for CRA + NIS2 Annex** — fragile parsing but unlocks legally-precise article cross-refs beyond what's in the XLSX.
- **Evidence Request List sheet (5,784 rows)** — audit prep workflow. Power-user feature for GRC teams.
- **Threat & Risk catalogues** — SCF has 50 threats + 48 risks as separate sheets. Could replace or supplement our existing technique-derived risk lens.
- **Revoked-attack-id replacement chain resolution** — v19 revoked T1562 etc. without setting `revoked_by_stix_id`. A backfill pass walking STIX `revoked-by` relationships could auto-redirect SCF mappings to their successors.

## Tier 1 + Tier 2 framework keys (v2 — final 22)

### Tier 1 — Global, high-demand (12)
```
nist-800-53-r5, nist-csf-v2, iso-27002-2022,
pci-dss-4, soc-2-tsc, hipaa-security-rule,
gdpr, eu-nis2, eu-cra, eu-ai-act,
cmmc-2, owasp-top10-2025
```

### Tier 2 — Sectoral / regional (10)
```
eu-dora, cis-controls-8-1 (ID-only — license restricts text),
nist-800-171-r3, fedramp-r5,
nerc-cip-2024, iec-62443-2-1 (umbrella for 2-1/3-3/4-2),
uk-cyber-essentials, au-essential-8,
nist-ai-rmf, mitre-attck-mitigations (already-modeled cross-ref)
```

Both lists drive `src/lib/scf-framework-registry.ts`. Everything else SCF ships defaults to Tier 3 (hidden behind "Show all 250+").

## Reviewer findings absorbed (v2)

| # | Source | Finding | Resolution |
|---|---|---|---|
| 1 | architect + postgres | ATT&CK ID drift silently corrupts counts | `is_unresolved` flag + `last_validated_attack_version` + classifier step at ingest. Real-world gap measured: 15/511 (3%) — defensible without waiting for SCF v19 |
| 2 | postgres | 5-table roll-up join too slow (~150ms p95) | Pre-compute `scf_group_compliance_summary` + `_software_` + `_sector_` at end of ingest → PK lookup, <10ms |
| 3 | postgres | UPSERT on 200K rows + partial-state reads | Shadow-table swap pattern (load `*_new`, atomic RENAME) for `scf_framework_refs` + 3 summary tables |
| 4 | postgres | Missing covering index | `idx_scf_attack_mappings_attack_covering (attack_id) INCLUDE (scf_id)` + composite `(scf_id, framework_key)` |
| 5 | postgres | Type mismatch | `scf_attack_mappings.attack_id` declared `VARCHAR(20)` (matches `techniques.attack_id`) |
| 6 | postgres | Overlap via trigger / matview is wrong | Ingest-end `INSERT INTO scf_framework_overlap` once per quarter |
| 7 | architect | Overlap matview built too late (Phase 8) | Moved to Phase 2 — required by `/compliance/<framework>` detail page |
| 8 | architect | Hand-curated registry brittle | `scf_framework_aliases` table — ingester populates, Tier-1 alias loss is a fail-loud condition |
| 9 | architect | License footer only on `/compliance/*` is wrong | Global footer credit — SCF data permeates entity pages |
| 10 | architect | Missing observability | Phase 8.5 added: orphan count surfaced in `/feed-status`, alias drift detection, slow-query alerting |
| 11 | architect | Coverage metric needs explainer | Inline tooltip (not just hover) on `/compliance` hub rows explaining the filtered count |
| 12 | architect | Roll-up perf untested before Phase 5 | Phase 1.5 added — perf budget commit before entity panels ship |
