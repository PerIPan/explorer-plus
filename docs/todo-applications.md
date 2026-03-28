# Application → CVE → Technique → APT — Checklist (v2)

## Phase 1: Schema + Bulk Ingestion
- [ ] Deploy `cve_details` table to production Neon
- [ ] Create `cve_weaknesses` junction table (multi-CWE per CVE)
- [ ] Create `applications` table (vendor, product, normalized slug)
- [ ] Create `affected_products` table (CVE ↔ app with version ranges)
- [ ] Create `capec_mappings` table (CWE → CAPEC → technique FK)
- [ ] Add all indexes (trigram, FK, bridge joins, materialized view)
- [ ] Create `app_technique_groups` materialized view
- [ ] Add `cve_count` trigger on `affected_products`
- [ ] Write `scripts/sync-capec-bridge.mjs` — STIX CAPEC → capec_mappings
- [ ] Run CAPEC bridge sync (~3K mappings)
- [ ] Write `scripts/ingest-cvelistv5.mjs` — local bulk parse from zip
- [ ] Run bulk ingestion (5 years, ~125K CVEs, ~10K apps)
- [ ] Refresh materialized view
- [ ] Verify linkage: pick 5 apps, confirm CVE→technique→group chain

## Phase 2: API
- [ ] `GET /api/v1/applications` — list, search, sort by cve_count
- [ ] `GET /api/v1/applications/:slug` — detail using materialized view
- [ ] Add `application` type to entities search
- [ ] Enhance CVE detail with affected_products + techniques
- [ ] Migrate CVE list page to query `cve_details` (not `ioc_entries`)

## Phase 3: Frontend
- [ ] Application list page (`/applications`)
- [ ] `ApplicationMapView` — 5 sections (CVEs, CWEs, techniques, actors, software)
- [ ] Application graph (app → CVEs → techniques → groups)
- [ ] Add to Relationships page (search, tabs, graph)
- [ ] Sidebar: new "Assets" section
- [ ] Technique 360: "Affected Applications" section
- [ ] CVE Detail: "Affected Applications" section

## Phase 4: Delta Sync (Vercel)
- [ ] `api/cron/ingest-cve-delta.ts` — daily delta zip from GitHub Releases
- [ ] `api/cron/sync-capec.ts` — monthly CAPEC refresh
- [ ] CISA KEV cross-reference (`is_kev` flag)

## Phase 5: Future
- [ ] MITRE ATLAS (separate plan)
