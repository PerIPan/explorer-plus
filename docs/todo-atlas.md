# MITRE ATLAS Integration — Checklist

## Phase 1: Schema + Data
- [ ] Create `atlas_xrefs` table (ATLAS ↔ ATT&CK technique cross-references)
- [ ] Add `atlas` to domain validation enums in all API handlers
- [ ] Write `scripts/sync-atlas.mjs` — YAML parse + upsert tactics/techniques/mitigations
- [ ] Run sync on local DB
- [ ] Run sync on Neon
- [ ] Add `atlas` to DomainContext domain selector
- [ ] Verify entities API returns ATLAS techniques when domain=atlas

## Phase 2: Matrix
- [ ] Verify matrix API handles domain=atlas
- [ ] Test ATLAS matrix rendering (16 tactics × ~60 techniques)
- [ ] Verify tactic sort order for ATLAS

## Phase 3: Technique 360
- [ ] ATLAS technique detail: maturity badge, ATT&CK xref link
- [ ] ATT&CK technique: "ATLAS AI Context" section for 34 cross-referenced techniques
- [ ] TechniqueMapView: show ATLAS mitigations

## Phase 4: Cross-Domain
- [ ] Application 360: "ATLAS Techniques" section for AI apps
- [ ] Search: ATLAS techniques appear in global search
- [ ] Data Model diagram: add ATLAS node
- [ ] Feed Status: add ATLAS card

## Phase 5: Ongoing
- [ ] Monthly Vercel cron for ATLAS sync
- [ ] Version tracking in feed_sync_log
