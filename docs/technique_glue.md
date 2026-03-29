# Technique Glue — How Data Comes Together

> Generated 2026-03-29. Production database: Neon (Vercel).

---

## 1. Table Inventory

**44 base tables + 1 materialized view** on production.

| Table | Rows | Purpose |
|-------|-----:|---------|
| `techniques` | 1,249 | ATT&CK + ATLAS techniques (990 ATT&CK, 155 ATLAS, ~100 sub-techniques) |
| `tactics` | 56 | ATT&CK + ATLAS tactics (40 ATT&CK, 16 ATLAS) |
| `threat_groups` | 191 | Threat actor profiles |
| `campaigns` | 56 | Named campaigns |
| `attack_software` | 914 | Malware & tools |
| `mitigations` | 369 | ATT&CK + ATLAS mitigations |
| `data_sources` | 42 | Detection data sources |
| `data_components` | 122 | Sub-components of data sources |
| `sectors` | 12 | Industry verticals |
| `cve_details` | 21,605 | CVE metadata (CVElistV5 + NVD + delta cron) |
| `cve_weaknesses` | 27,497 | Multi-CWE per CVE (real CWEs + synthetic CTID entries) |
| `applications` | 11,074 | Vendor/product pairs (from CPE) |
| `affected_products` | 80,735 | CVE↔application junction with version ranges |
| `capec_mappings` | 1,483 | CWE→CAPEC→ATT&CK bridge + CTID synthetic entries |
| `ioc_entries` | 5,841 | IOCs from OTX, abuse.ch, CISA KEV |
| `technique_iocs` | 27,035 | IOC↔technique links (inferred + confirmed) |
| `threat_reports` | 80 | OTX pulses + RSS reports |
| `report_techniques` | 293 | Report↔technique links |
| `sigma_rules` | 3,105 | Sigma detection rules per technique |
| `atomic_tests` | 1,773 | Atomic Red Team tests per technique |
| `defensive_mappings` | 5,036 | D3FEND countermeasure mappings |
| `detection_strategies` | 691 | MITRE Cyber Analytics Repository |
| `detection_analytics` | 1,739 | Analytics within detection strategies |
| `external_actors` | 514 | ThaiCERT actor profiles |
| `atlas_xrefs` | 34 | ATLAS↔ATT&CK technique cross-references |
| `nist_controls` | 5,264 | NIST 800-53 mappings |
| `engage_mappings` | 1,113 | MITRE Engage activity mappings |
| `cloud_control_mappings` | 1,454 | Azure/GCP control mappings |
| `veris_mappings` | 1,092 | VERIS framework mappings |
| `react_actions` | 216 | RE&CT response actions |
| `a2a_requests` | 13 | A2A query log |
| `feed_sync_log` | 232 | Cron job run history |
| `seed_metadata` | 6 | ATT&CK version info per domain |
| **`app_technique_groups`** (MV) | **1,415,616** | Pre-computed app→technique→group chains |

### Junction Tables (many-to-many)

| Junction | Left | Right | Rows |
|----------|------|-------|-----:|
| `technique_tactics` | technique | tactic | 1,502 |
| `technique_data_components` | technique | data_component | 3,024 |
| `group_techniques` | group | technique | 4,750 |
| `group_software` | group | software | 1,130 |
| `group_campaigns` | group | campaign | 26 |
| `group_sectors` | group | sector | 396 |
| `campaign_techniques` | campaign | technique | 1,126 |
| `campaign_software` | campaign | software | 153 |
| `software_techniques` | software | technique | 12,128 |
| `mitigation_techniques` | mitigation | technique | 2,187 |

---

## 2. Data Ingestion Sources

### Bulk Scripts (manual, run once or occasionally)

| Script | Source | Tables Written | Notes |
|--------|--------|----------------|-------|
| `seed` (Vite plugin) | MITRE ATT&CK STIX bundle | techniques, tactics, groups, software, campaigns, mitigations, data_sources, data_components + all junction tables | Full ATT&CK knowledge base per domain |
| `sync-atlas.mjs` | ATLAS YAML from GitHub | techniques, tactics, mitigations, atlas_xrefs, technique_tactics, mitigation_techniques | Writes domain='atlas-attack' |
| `sync-capec-bridge.mjs` | CAPEC STIX from GitHub | capec_mappings | DELETE+INSERT, ~1,483 rows. Builds CWE→CAPEC→technique bridge |
| `ingest-cvelistv5.mjs` | CVElistV5 zip from GitHub | cve_details, cve_weaknesses, applications, affected_products | Bulk CVE ingest with CWE filter. Only ingests CVEs that have CWEs with a technique path |
| `sync-ctid-cve-mappings.mjs` | CTID CSV from GitHub | capec_mappings (synthetic CTID-DIRECT entries), cve_weaknesses (synthetic CTID-Txxxx CWEs), technique_iocs | Hand-curated CVE→technique links. Creates synthetic CWE+CAPEC entries so the MV chain works |
| `enrich-cve-products.mjs` | CVElistV5 individual JSONs | cve_weaknesses, applications, affected_products | Backfills affected_products for CVEs missing CPE data |
| `sync-frameworks.mjs` | Multiple STIX/JSON sources | nist_controls, engage_mappings, veris_mappings, cloud_control_mappings, detection_strategies, detection_analytics | NIST, Engage, VERIS, cloud controls, CAR analytics |
| `sync-sigma.mjs` | SigmaHQ GitHub rules | sigma_rules | |
| `sync-atomic.mjs` | Atomic Red Team GitHub | atomic_tests | |
| `sync-thaicert.mjs` | ThaiCERT JSON | external_actors | |
| `sync-detection-strategies.mjs` | MITRE CAR | detection_strategies, detection_analytics | |

### Cron Jobs (automated, scheduled on Vercel)

| Cron | Source | Tables Written | Schedule |
|------|--------|----------------|----------|
| `ingest-cve-delta` | NVD API (last 48h) | cve_details, cve_weaknesses, applications, affected_products | Daily |
| `ingest-otx` | AlienVault OTX API | threat_reports, report_techniques, ioc_entries, technique_iocs | Periodic |
| `ingest-cisa-kev` | CISA KEV JSON | ioc_entries, cve_details.is_kev | Daily |
| `ingest-abuse-ch` | ThreatFox + MalwareBazaar | ioc_entries, technique_iocs | Daily |
| `ingest-rss` | DFIR Report, Unit42, MS Security, Talos | threat_reports, report_techniques | Daily |
| `enrich-nvd` | NVD API (per-CVE) | cve_details, ioc_entries.description | Periodic, processes IOC CVEs not yet in cve_details |
| `enrich-vt` | VirusTotal API | ioc_entries (vt_* columns) | Periodic |
| `sync-d3fend` | D3FEND API | defensive_mappings | Periodic, 15 techniques/run, resumable |

---

## 3. The Three Paths: CVE → Technique

This is the core "glue" — how a CVE vulnerability connects to an ATT&CK technique.

### Path 1: CAPEC Bridge (primary, 20,108 CVEs)
```
CVE → cve_weaknesses.cwe_id → capec_mappings.cwe_id → capec_mappings.technique_id → techniques
```

**How it works:** A CVE has CWEs (e.g., CWE-200 "Information Exposure"). CAPEC maps CWE-200 to CAPEC patterns that reference ATT&CK techniques (e.g., T1082 "System Information Discovery"). The CAPEC STIX bundle is the authoritative source.

**Coverage:** 194 unique CWEs map to 201 techniques. Only ~52% of CWEs in the data have this path.

**Gap:** Major CWEs like CWE-89 (SQL Injection, 2,764 CVEs), CWE-79 (XSS, 965 CVEs), CWE-77 (Command Injection, 286 CVEs) have CAPEC entries but MITRE has **not mapped those CAPECs to ATT&CK techniques**. This is a gap in MITRE's own data — their CAPEC→ATT&CK mapping only covers ~200 of 559 CAPEC patterns.

### Path 2: IOC Path (secondary, 489 CVEs)
```
CVE → ioc_entries(type='cve') → technique_iocs → techniques
```

**How it works:** CVEs appear as IOC entries (from OTX, CISA KEV, abuse.ch). The `technique_iocs` junction links them to techniques via:
- OTX: pulse attack_ids directly reference ATT&CK techniques
- abuse.ch: malware family → software_techniques → techniques (inferred)
- CISA KEV: CWE→CAPEC bridge after enrichment (`linkCveTechniquesViaCwe()`)

**Overlap:** 317 CVEs appear in BOTH paths.

### Path 3: CTID Direct (supplementary, 198 CVEs)
```
CVE → cve_weaknesses(CTID-Txxxx) → capec_mappings(CTID-DIRECT) → techniques
```

**How it works:** MITRE's Center for Threat-Informed Defense maintains hand-curated CVE→technique mappings. Since our CAPEC bridge needs CWE→CAPEC→technique, CTID uses a hack: creates synthetic CWE IDs like `CTID-T1190` and synthetic CAPEC entries with `capec_id='CTID-DIRECT'`. This piggybacks on the same join path as Path 1.

**Note:** CTID mappings are mostly for 2010-2020 era CVEs. New CVEs won't get CTID mappings.

### Combined Coverage
| Metric | Count |
|--------|------:|
| CVEs with ANY technique path | 20,280 |
| CVEs with NO technique path | 1,325 |
| Total CVEs | 21,605 |

---

## 4. CVE → Application → Threat Group Chain

This is the chain that powers the 360 views.

### Live Query Path (used in API endpoints)
```
CVE → affected_products → applications
CVE → cve_weaknesses → capec_mappings → techniques → group_techniques → threat_groups
```

### Materialized View (pre-computed, 1.4M rows)
```sql
app_technique_groups AS
  SELECT DISTINCT ap.application_id, cm.attack_technique_id, t.id, t.name, tg.attack_id, tg.name
  FROM affected_products ap
  JOIN cve_weaknesses cw     ON cw.cve_id = ap.cve_id
  JOIN capec_mappings cm     ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
  JOIN techniques t          ON t.id = cm.technique_id
  JOIN group_techniques gt   ON gt.technique_id = t.id
  JOIN threat_groups tg      ON tg.id = gt.group_id
```

**Important:** The MV only uses the **CAPEC bridge path**. It does NOT include CTID or IOC-path technique links. This means applications linked only via CTID CVEs may show fewer techniques/groups than expected.

**Used by:**
- `/api/v1/applications/[vendor]/[product]` — techniques and groups tabs
- `/api/v1/applications` — techniqueCount and groupCount columns
- `/api/v1/sectors/[slug]/relationships` — vulnerable apps
- `/api/v1/feed/intelligence/[attackId]` — affected applications

**Refresh:** `REFRESH MATERIALIZED VIEW CONCURRENTLY` after bulk ingestion and daily delta cron.

---

## 5. ATLAS Cross-Reference Chain

ATLAS techniques are in domain `atlas-attack`. They don't have native groups/software/campaigns.

### 2nd-Order Discovery
```
ATLAS technique → atlas_xrefs → ATT&CK technique → group_techniques → threat_groups
ATLAS technique → atlas_xrefs → ATT&CK technique → software_techniques → attack_software
ATLAS technique → atlas_xrefs → ATT&CK technique → campaign_techniques → campaigns
```

**34 cross-references** connect ATLAS to ATT&CK. The dashboard uses this for ATLAS domain group/software/campaign counts.

---

## 6. Sector → Threat Landscape Chain

```
sector → group_sectors → threat_groups → group_techniques → techniques
                                       → group_software   → attack_software
                                       → group_campaigns  → campaigns
```

**CVEs for sectors** use two parallel paths:
```
sector → groups → techniques → technique_iocs → ioc_entries(cve) → cve_details   (IOC path)
sector → groups → techniques → capec_mappings → cve_weaknesses → cve_details     (CAPEC reverse)
```

Both limited to 200 results per branch to prevent timeouts.

---

## 7. Report → Technique Chain

```
RSS/OTX → threat_reports → report_techniques → techniques
```

Technique extraction:
- **RSS**: Regex `T\d{4}(\.\d{3})?` against title + description
- **OTX**: `pulse.attack_ids` array (direct from AlienVault)

---

## 8. IOC → Technique Chain

```
ThreatFox IOC → malware_family → attack_software(name/alias match) → software_techniques → technique_iocs
OTX IOC       → pulse.attack_ids → techniques → technique_iocs
CISA KEV CVE  → enrich with NVD CWE → linkCveTechniquesViaCwe() → technique_iocs
```

**Confidence levels:** `confirmed`, `sandbox_verified`, `inferred`

---

## 9. Framework Mapping Chains

| Framework | Chain |
|-----------|-------|
| NIST 800-53 | `nist_controls.technique_id → techniques` |
| D3FEND | `defensive_mappings.technique_id → techniques` |
| MITRE Engage | `engage_mappings.technique_id → techniques` |
| Cloud Controls | `cloud_control_mappings.attack_technique_id` |
| VERIS | `veris_mappings (via technique match)` |
| Sigma | `sigma_rules.technique_id → techniques` |
| Atomic Red Team | `atomic_tests.technique_id → techniques` |
| Detection Strategies | `detection_strategies.attack_technique_id` (text match, not FK) |
| Detection Analytics | `detection_analytics.det_id → detection_strategies.det_id` |

---

## 10. Known Inconsistencies & Gaps

### DATA GAPS (in MITRE's own data)

| Issue | Impact | CVEs Affected |
|-------|--------|:---:|
| **CWE-89 (SQL Injection) has no ATT&CK mapping via CAPEC** | 2,764 CVEs can't reach any technique | 2,764 |
| **CWE-79 (XSS) has no ATT&CK mapping via CAPEC** | Same — MITRE hasn't mapped these CAPECs | 965 |
| **CWE-77 (Command Injection) — no mapping** | | 286 |
| **CWE-78 (OS Command Injection) — no mapping** | | — |
| **CWE-22 (Path Traversal) — no mapping** | | 116 |
| **CWE-502 (Deserialization) — no mapping** | | 118 |
| **~48% of CWEs in our data have no technique path** | 194 of 370 unique CWEs connect | — |

These are confirmed against MITRE's official CAPEC pages — the CAPEC entries exist but have no ATT&CK `external_references` in the STIX bundle.

### OUR DATA ISSUES

| Issue | Impact | Fix |
|-------|--------|-----|
| **1,000 CVEs missing from `cve_weaknesses`** | CVEs from early delta cron runs (Mar 23-24) have CWE in `cve_details.cwe_id` but not in `cve_weaknesses`. The CAPEC bridge can't reach them. | Run: `INSERT INTO cve_weaknesses (cve_id, cwe_id) SELECT cve_id, cwe_id FROM cve_details WHERE cwe_id LIKE 'CWE-%' AND NOT EXISTS (SELECT 1 FROM cve_weaknesses cw WHERE cw.cve_id = cve_details.cve_id AND cw.cwe_id = cve_details.cwe_id) ON CONFLICT DO NOTHING;` then refresh MV |
| **126 CVEs have `cve_details.cwe_id` that differs from `cve_weaknesses`** | Harmless — CVE has multiple CWEs, `cve_details.cwe_id` stores just the first | No fix needed |
| **1 unresolved CAPEC FK** | CAPEC-641/CWE-706 → T1574.002: technique_id is NULL | Technique T1574.002 may not exist as a separate row (sub-technique resolution) |
| **`enrich-nvd` writes `nvd_enriched_at` but `ingest-cve-delta` does not** | No functional impact — `enrich-nvd` only processes IOC CVEs missing from `cve_details`, and delta cron already populates those | Cosmetic inconsistency |
| **MV uses CAPEC-only path** | Applications linked only via CTID show fewer groups/techniques in the 360 view | Could add CTID to MV definition (low priority — only 198 CVEs) |
| **2,623 CVEs missing CVSS score** | Likely analysis-pending CVEs or rejects | NVD hasn't scored them yet |
| **351 CVEs missing CWE entirely** | No technique path possible | Wait for NVD assignment |

### FUNCTIONAL OVERLAPS

| Area | Details |
|------|---------|
| **`enrich-nvd` vs `ingest-cve-delta`** | Both fetch from NVD API but serve different purposes. `enrich-nvd` enriches IOC CVEs (from OTX/KEV/abuse.ch) one-by-one. `ingest-cve-delta` bulk-fetches all CVEs modified in last 48h. Now that delta runs daily, `enrich-nvd` processes 0 pending CVEs — it's effectively superseded. |
| **`cve_details.cwe_id` vs `cve_weaknesses`** | Redundant — `cwe_id` column stores first CWE, `cve_weaknesses` stores all. All queries now use `cve_weaknesses` for the bridge. The column is legacy. |
| **IOC path vs CAPEC path for CVEs** | Both paths are queried with UNION in API endpoints. 317 CVEs appear in both. The API deduplicates by `attack_id` and labels the source. |

---

## 11. Data Flow Diagram

```
                                    ┌─────────────┐
                    ┌──────────────>│ techniques  │<─────────────────────┐
                    │               └──────┬──────┘                     │
                    │                      │                            │
              technique_id           technique_id                 technique_id
                    │                      │                            │
              ┌─────┴──────┐    ┌──────────┴──────────┐    ┌───────────┴──────────┐
              │capec_mappings│    │  group_techniques   │    │  technique_iocs      │
              │ cwe→capec→T │    │  group↔technique     │    │  ioc↔technique       │
              └─────┬──────┘    └──────────┬──────────┘    └───────────┬──────────┘
                    │                      │                            │
                 cwe_id               group_id                      ioc_id
                    │                      │                            │
              ┌─────┴──────┐    ┌──────────┴──────────┐    ┌───────────┴──────────┐
              │cve_weaknesses│   │   threat_groups      │    │    ioc_entries        │
              │ cve↔cwe     │    │   actor profiles     │    │ IP, hash, CVE, URL   │
              └─────┬──────┘    └──────────┬──────────┘    └──────────────────────┘
                    │                      │                  Sources: OTX, abuse.ch,
                 cve_id               group_id                  CISA KEV
                    │                      │
              ┌─────┴──────┐    ┌──────────┴──────────┐
              │ cve_details │    │   group_sectors      │
              │ CVE metadata│    │   group↔sector       │
              └─────┬──────┘    └──────────┬──────────┘
                    │                      │
                 cve_id               sector_id
                    │                      │
              ┌─────┴──────────┐    ┌──────┴──────┐
              │affected_products│    │   sectors    │
              │ cve↔application │    │ 12 verticals│
              └─────┬──────────┘    └─────────────┘
                    │
              application_id
                    │
              ┌─────┴──────┐
              │ applications│
              │vendor/product│
              └─────────────┘

    ═══════════════════════════════════════════════
    Materialized View: app_technique_groups (1.4M)
    affected_products → cve_weaknesses → capec_mappings
    → techniques → group_techniques → threat_groups
    ═══════════════════════════════════════════════
```

---

## 12. API Endpoints and Their Join Patterns

| Endpoint | Primary Path | Secondary Path | Key Tables |
|----------|-------------|----------------|------------|
| `GET /cves` | `cve_details` direct | sources from `ioc_entries`, technique count from CAPEC+IOC UNION, apps from `affected_products` | CTE: page first, then enrich |
| `GET /cves/:id` | `cve_details` + `cve_weaknesses` + `affected_products` | Techniques: IOC path UNION CAPEC path. Reports: via shared techniques | 7 parallel queries |
| `GET /feed/intelligence/:id` | `techniques` → all feeds | CVEs: IOC + CAPEC UNION. Apps: via MV | 8 parallel queries |
| `GET /applications/:v/:p` | `applications` → `affected_products` | Techniques + groups from MV. Weaknesses from `cve_weaknesses` | 5 parallel queries |
| `GET /sectors/:slug/relationships` | `group_sectors` → groups → JOINs | CVEs: IOC + CAPEC reverse (LIMIT 200 each). Apps: via MV | 6 parallel queries |
| `GET /dashboard` | Counts from entity tables | 2nd-order ATLAS via `atlas_xrefs` UNION | 6 parallel queries, 4 code paths per filter combo |
| `GET /groups/:id` | `threat_groups` → junction tables | Sectors, techniques (with sub-tech), campaigns, software | Multiple queries |
| `POST /api/a2a` | Gemini → internal API calls | Same paths as above via `callInternalApi()` | Rate-limited, logged |
