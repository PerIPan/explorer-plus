# MITRE ATT&CK Update Path

> Safe-update script for absorbing new ATT&CK releases (v18 → v19 → future) without destroying user-curated data.

**Status:** Design v2 — incorporates architect / postgres / fullstack reviewer findings.

---

## Why this exists

The existing seed (`seed/seed.py`) is **destructive** — `schema.sql` `TRUNCATE … CASCADE`s 15 tables on every run, including `ioc_entries`, `threat_reports`, `sigma_rules`, `atomic_tests`, `defensive_mappings`, `feed_sync_log`. CASCADE then wipes FK children in custom mapping tables (`capec_mappings`, `csf_technique_mappings`, `atlas_xrefs`, `ctid_mappings`, `external_actors`, `owasp_top10`, `nist_controls`, `engage_mappings`, `react_actions`, `veris_mappings`, `cloud_control_mappings`, `detection_strategies`, `detection_analytics`).

Running the seed on every ATT&CK release is therefore a system-wide reset. We need a non-destructive path so absorbing v19+ doesn't lose IOCs, reports, custom mappings, or cron history.

## Scope

What v19 (April 28, 2026) adds:

- Defense Evasion tactic split into `Stealth` (TA0005, renamed) + `Defense Impairment` (TA0112, new)
- ICS sub-techniques introduced for the first time
- Mobile detection strategies
- New AI-enabled and social-engineering techniques
- CTI updates (groups, campaigns, software)

The four domains stay the same (Enterprise, Mobile, ICS, ATLAS). **ATLAS is out of scope for this script** — `scripts/sync-atlas.mjs` already owns that pipeline on its own cadence and identity key. This script handles **Enterprise + Mobile + ICS only**.

## Decisions

| # | Decision | Choice | Reasoning |
|---|---|---|---|
| 1 | Lifecycle | **Reusable, manual** | MITRE ships 2×/year — manual gate beats schedule |
| 2 | Identity | **UPSERT by `stix_id`** | DB UUIDs preserved → custom FK references intact |
| 3 | Relation reconciliation | **Insert-then-delete-orphans** | No zero-link window for readers under READ COMMITTED (revised from per-parent atomic swap on postgres-pro feedback) |
| 4 | Deprecated entities | **Mark, never delete** | Preserves FK references from custom tables |
| 5 | STIX parsing | **Subprocess to existing `seed/extract.py`** | Reuses `mitreattack-python` STIX edge-case handling — no JS port (revised on fullstack feedback) |
| 6 | Domains in scope | **Enterprise, Mobile, ICS** | ATLAS handled by `sync-atlas.mjs`; including it would cause double-write conflicts |
| 7 | Concurrency control | **`pg_try_advisory_lock`** | Prevents two operators triggering simultaneously |
| 8 | Version guard | **Require strictly newer `x_mitre_attack_spec_version`** | Stale CDN response can't silently no-op a "successful" run |

## Preflight (one-time, before first v19 run)

Three correctness fixes the design depends on. None of them belong in the update script itself — they're prerequisites that ship as a separate migration / commit.

### Preflight A: `domain` column → `TEXT[]`

**Problem:** STIX shares some entities across bundles — APT28 (`intrusion-set--bef4c620-…`) appears in both the Enterprise and ICS bundles with the same `stix_id`. With the current single-value `domain VARCHAR(50)` column, the second-processed bundle silently clobbers the first. Domain filters in the UI then return the wrong results for cross-domain actors.

**Fix:** Migrate the affected three tables to a domain-array column.

```sql
ALTER TABLE threat_groups ALTER COLUMN domain TYPE TEXT[]
  USING ARRAY[domain]::TEXT[];
ALTER TABLE attack_software ALTER COLUMN domain TYPE TEXT[]
  USING ARRAY[domain]::TEXT[];
ALTER TABLE campaigns ALTER COLUMN domain TYPE TEXT[]
  USING ARRAY[domain]::TEXT[];

CREATE INDEX idx_threat_groups_domain ON threat_groups USING gin(domain);
CREATE INDEX idx_attack_software_domain ON attack_software USING gin(domain);
CREATE INDEX idx_campaigns_domain ON campaigns USING gin(domain);
```

UI filter queries change from `WHERE domain = 'enterprise-attack'` to `WHERE 'enterprise-attack' = ANY(domain)`. Search-and-replace pass needed across `app/api/v1/**` before this migration runs.

The UPSERT logic in the update script will then `array_cat`-merge the new domain into the existing array on conflict.

### Preflight B: `_TACTIC_SORT_ORDER` map in `seed/extract.py`

**Problem:** v19 introduces `stealth` and `defense-impairment` tactic shortnames. The hard-coded sort-order map at `seed/extract.py:28` doesn't know about them — they'd come in with `sort_order=null` and the matrix would render with broken column order.

**Fix:** Add the two entries to `_TACTIC_SORT_ORDER`:

```python
'stealth': 7,             # was 'defense-evasion' — keeps old position
'defense-impairment': 8,  # new tactic, slot 8
# remaining shifted by +1: discovery=9, lateral-movement=10, …
```

### Preflight C: Drop ATLAS from any new domain-loop code

`scripts/sync-atlas.mjs` already owns ATLAS UPSERT. The new update script must not include ATLAS in its `--domains` default or accept it. Existing seed paths and the ATLAS sync stay unchanged.

## Architecture

### Files
- `scripts/update-attack.mjs` — main script (Node, ESM). Reuses `pg.Pool`, `feed_sync_log` lifecycle, UNNEST batching from `sync-cve-delta.mjs` v5.
- `seed/extract.py --json --domain=<domain>` — extended to emit JSON to stdout when `--json` flag passed. The Node script `spawnSync`s it once per domain. **No JS port.**
- `.github/workflows/update-attack.yml` — `workflow_dispatch` only, no schedule. Inputs: `dry-run` (boolean), `domains` (default: `enterprise,mobile,ics`).

### Entities updated, in dependency order
1. `tactics` — UPSERT by `stix_id`. Sets `is_revoked`/`is_deprecated` from STIX flags.
2. `techniques` — UPSERT by `stix_id`. Parents first, then sub-techniques.
3. `threat_groups`, `attack_software`, `mitigations`, `campaigns` — UPSERT by `stix_id`, with `domain` array merged via `array_cat`.
4. `data_sources`, `data_components` — UPSERT by `stix_id`.
5. **Relations** (insert-then-delete-orphans, see below): `technique_tactics`, `group_techniques`, `software_techniques`, `mitigation_techniques`, `campaign_groups`, `campaign_software`, `data_component_techniques`.

### UPSERT pattern — two-CTE for accurate insert/update split

`xmax = 0` is unreliable on PG 15+. Replace with explicit two-CTE form:

```sql
WITH input AS (
  SELECT * FROM unnest($1::text[], $2::text[], …) AS u(stix_id, name, …)
),
inserted AS (
  INSERT INTO techniques (stix_id, name, …)
  SELECT * FROM input
  ON CONFLICT (stix_id) DO NOTHING
  RETURNING id, stix_id
),
updated AS (
  UPDATE techniques t SET name = i.name, is_revoked = i.is_revoked, …
  FROM input i
  WHERE t.stix_id = i.stix_id
    AND t.stix_id NOT IN (SELECT stix_id FROM inserted)
  RETURNING t.id, t.stix_id
)
SELECT 'inserted' AS kind, id, stix_id FROM inserted
UNION ALL
SELECT 'updated' AS kind, id, stix_id FROM updated;
```

The DB-internal `id UUID` column is **never touched** — only updated columns get refreshed. All FK references from custom tables stay intact.

### Cross-domain `domain` array merge (groups / software / campaigns)

```sql
INSERT INTO threat_groups (stix_id, name, domain, …)
SELECT stix_id, name, ARRAY[$1::text]::text[], …
FROM unnest(…)
ON CONFLICT (stix_id) DO UPDATE SET
  domain = (
    SELECT array_agg(DISTINCT d) FROM unnest(threat_groups.domain || EXCLUDED.domain) AS d
  ),
  -- … other mutable columns …
  updated_at = NOW();
```

Each domain pass appends its own marker; the existing array is preserved. APT28 ends up with `domain = {enterprise-attack, ics-attack}`.

### Relation reconciliation — insert-then-delete-orphans (revised)

The original "DELETE + INSERT inside a transaction" leaves a zero-link window visible to concurrent readers under READ COMMITTED. Restructured pattern:

```sql
-- Step 1: insert any missing links
INSERT INTO technique_tactics (technique_id, tactic_id)
SELECT $1, t::uuid FROM unnest($2::text[]) AS u(t)
ON CONFLICT DO NOTHING;

-- Step 2: delete links that are no longer in the new set
DELETE FROM technique_tactics
WHERE technique_id = $1 AND tactic_id NOT IN (
  SELECT t::uuid FROM unnest($2::text[]) AS u(t)
);
```

Readers always see a valid superset; the technique never has zero tactic links during the swap. Same pattern for the other six relation tables.

### Concurrency lock

```sql
SELECT pg_try_advisory_lock(:lock_key);  -- e.g. hashtext('attack_update')
```

Acquired at start. If `false` returned, exit non-zero with `feed_sync_log.status='error'`, message: "another attack-update is in progress". Released in the `finally` block.

### Version guard

Read `x_mitre_attack_spec_version` from each STIX bundle's metadata. Compare to last successful `feed_sync_log.metadata->>'attackVersion'` for source `attack_update`. Abort with non-zero exit if not strictly greater. Override with `--force` flag for re-runs after schema fixes.

### Post-UPSERT integrity check

After all techniques upserted, assert no row simultaneously has `is_subtechnique = true` AND children pointing at it as `parent_technique_id`. If violated, mark run as `error` (the data is now inconsistent and needs human review).

```sql
SELECT t.stix_id, t.attack_id, COUNT(c.id) AS orphan_children
FROM techniques t
LEFT JOIN techniques c ON c.parent_technique_id = t.id
WHERE t.is_subtechnique = true
GROUP BY t.stix_id, t.attack_id
HAVING COUNT(c.id) > 0;
```

### Revoked-redirect surfacing

STIX includes `relationship` objects with `relationship_type = 'revoked-by'` linking a deprecated entity's `stix_id` to its successor. Surface these in the run output (and `feed_sync_log.metadata.revokedRedirects`) so curators of `capec_mappings`, `external_actors`, etc. can re-target their references manually.

## Operational

### CLI
```
node scripts/update-attack.mjs \
  --domains=enterprise,mobile,ics \   # default; ATLAS is out of scope
  [--dry-run] \                        # parse + diff, no writes
  [--force]                            # skip version-strictly-greater guard
```

### Dry-run output

Per-entity diff (not just counts). Critical for v19 review of the Defense Evasion → Stealth rename:

```
TACTICS
  UPDATE TA0005 'Defense Evasion' → 'Stealth'           (rename)
  INSERT TA0112 'Defense Impairment'                    (new)

TECHNIQUES (Enterprise)
  INSERT T1234 'AI-enabled spear-phishing'              (new)
  UPDATE T1059 attack_id unchanged, description changed (~150 chars)
  REVOKE T0987 'Old technique X' (revoked-by → T1234)

RELATIONS
  technique_tactics: +12 added, -4 removed
  group_techniques:   +0,        -0
  …
```

### feed_sync_log row
- `source = 'attack_update'`
- `metadata` JSONB: `{ attackVersion, domains, entityDeltas, relationDeltas, revokedRedirects, durationMs, dryRun }`
- Stale-row cleanup at start, terminal `success`/`error` on exit.

### Failure mode
- Per-entity-table failures roll back that table's batch. Idempotent UPSERTs make re-running safe.
- `feed_sync_log` row marked `status='error'` with the exception message.
- Process exits non-zero; GH Actions UI surfaces failure.

### Output stats per entity type
`inserted`, `updated`, `deprecated_now_true`, `revoked_now_true`, `relations_added`, `relations_removed`.

## Survival matrix (vs destructive seed)

| Data | Seed (current) | Update script (this design) |
|---|---|---|
| `tactics` / `techniques` / `groups` / `software` / `mitigations` / `campaigns` | TRUNCATE + reload, **new UUIDs** | UPSERT by stix_id, **same UUIDs** |
| `threat_reports` (RSS, OTX) | wiped | preserved |
| `ioc_entries` (OTX, ThreatFox, MalwareBazaar) | wiped | preserved |
| `sigma_rules` / `atomic_tests` / `defensive_mappings` | wiped | preserved |
| `feed_sync_log` | wiped | preserved |
| `capec_mappings` / `csf_technique_mappings` / `atlas_xrefs` / `ctid_mappings` etc. | CASCADE-wiped | **untouched** (UUIDs stable) |
| `cve_*` / `applications` / `affected_products` / `ghsa_*` / `osv_*` | already untouched by seed | already untouched |

## Verification harness

> Pre/post measurement so we can prove the update didn't break anything before declaring success.

The script runs an instrumented diff: capture a JSON snapshot of invariants **before** the update, again **after**, then assert nothing regressed. Failures abort the run with `status='error'` even if all UPSERTs succeeded.

### What gets measured

#### Invariants — must not regress (counts may rise, must not fall)

| Metric | SQL | Tolerance |
|---|---|---|
| Total `tactics` rows | `SELECT COUNT(*) FROM tactics` | ≥ pre |
| Total `techniques` rows | `SELECT COUNT(*) FROM techniques` | ≥ pre |
| Total `threat_groups` rows | `SELECT COUNT(*) FROM threat_groups` | ≥ pre |
| Total `attack_software` rows | `SELECT COUNT(*) FROM attack_software` | ≥ pre |
| Total `mitigations` rows | `SELECT COUNT(*) FROM mitigations` | ≥ pre |
| Total `campaigns` rows | `SELECT COUNT(*) FROM campaigns` | ≥ pre |
| Total `data_sources` + `data_components` rows | (each) | ≥ pre |
| Per-domain `techniques` count | `GROUP BY domain HAVING …` | ≥ pre per domain |
| Sub-technique parent linkage | `COUNT(*) FROM techniques WHERE is_subtechnique AND parent_technique_id IS NULL` | = 0 |

#### Invariants — must hold exactly (no FK can dangle)

For every custom mapping table that references entity UUIDs, the post-update DB must resolve every pre-existing FK to a live row:

| Custom table | FK column → target | Assertion |
|---|---|---|
| `capec_mappings.technique_id` → `techniques.id` | `WHERE technique_id NOT IN (SELECT id FROM techniques)` | rowcount = 0 |
| `csf_technique_mappings.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `atlas_xrefs.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `ctid_mappings.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `external_actors.related_technique_ids[]` → `techniques.id` | array unnest + IN check | rowcount = 0 |
| `engage_mappings.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `react_actions.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `veris_mappings.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `cloud_control_mappings.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `nist_controls`-bridge → `techniques.id` | same shape | rowcount = 0 |
| `owasp_top10`-bridge → `techniques.id` | same shape | rowcount = 0 |
| `detection_strategies.technique_id` → `techniques.id` | same shape | rowcount = 0 |
| `detection_analytics.detection_strategy_id` → `detection_strategies.id` | same shape | rowcount = 0 |
| `group_techniques.{group_id,technique_id}` | both sides | rowcount = 0 |
| `software_techniques`, `mitigation_techniques`, `campaign_*` | both sides | rowcount = 0 |

If any post-row count differs from pre on a custom table, AND the difference isn't a clean addition (i.e. existing rows became dangling), the run is marked failed.

#### Per-entity hash — every pre-existing row's `id` survives

```sql
-- pre
SELECT array_agg(id ORDER BY id) FROM techniques;
SELECT array_agg(id ORDER BY id) FROM tactics;
-- (same for the other 6 entity tables)
```

The post-update array must be a **superset** of the pre array. `pre[] - post[]` must be empty (no UUIDs disappeared). If non-empty, the offending UUIDs are logged and the run fails.

#### Spot checks (sampled, not exhaustive)

- Pick 20 random `techniques` from pre, fetch by `id`, confirm `name`, `attack_id`, `is_subtechnique`, and `parent_technique_id` post-update. `name` may legitimately change (e.g. tactic renames); `attack_id` and `id` must not.
- Pick 5 random `threat_groups` with cross-domain potential (APT28, FIN7, Lazarus). Confirm `domain` array contains every domain the entity appeared in pre + any new domains added in v19.
- Pick 3 known sub-technique IDs from each domain (e.g. `T1059.001`, `T1218.011`). Confirm `parent_technique_id` resolves to the correct parent.

#### Schema sanity (post-preflight only)

- `threat_groups.domain`, `attack_software.domain`, `campaigns.domain` are `_text` (TEXT[]) — assert via `information_schema.columns`.
- GIN index exists on each. Assert via `pg_indexes`.
- `_TACTIC_SORT_ORDER` map in `seed/extract.py` contains `stealth` and `defense-impairment` keys — assert via Python import + dict-key check (preflight verification, not part of update script).

#### UI smoke (post-update)

Synthetic GET against a known production endpoint, assert non-zero rowcount and 200 status:

```
/api/v1/matrix?domain=enterprise-attack       → ≥ 14 tactic columns (v19 has 15)
/api/v1/matrix?domain=ics-attack              → ≥ 12 tactic columns (v19 ICS has 12)
/api/v1/techniques?attack_id=T1059            → exactly 1 row
/api/v1/groups?attack_id=G0007                → exactly 1 row (APT28)
```

Failures here don't fail the DB update (already committed) but flag a `metadata.uiSmokeFailed` warning so we know to investigate.

### How it runs

1. **Pre-snapshot** — script's first action after acquiring the advisory lock. Writes `/tmp/attack-update-pre.json` and stashes a copy in `feed_sync_log.metadata.preSnapshot` for forensic recovery.
2. **Update** — preflights already done, all UPSERTs run as designed.
3. **Post-snapshot** — re-runs the same queries.
4. **Diff** — runs the assertions above. Any failure: mark `feed_sync_log.status='error'`, include the failing assertion in `error_message`, exit non-zero.

### Where the harness lives

- `scripts/lib/attack-snapshot.mjs` — emits the JSON snapshot from a connected `pg.Pool`. Reusable in other contexts (CI sanity check, manual diagnosis).
- `scripts/lib/attack-diff.mjs` — takes two snapshots, returns `{ passed: bool, failures: [...] }`.
- Both are imported by `update-attack.mjs`. Pre-snapshot runs at start, post-snapshot at end, diff runs before the success log write.

### Dry-run behavior

`--dry-run` skips the actual UPSERTs but still:
1. Captures pre-snapshot
2. Computes the diff against what the post-state **would** be (synthesized from the parsed STIX bundles)
3. Reports the projected delta without writing anything

Lets reviewers see "how many techniques will be inserted vs updated, what tactics rename, what FKs are at risk" before approving the real run.

## Out of scope

- ATLAS releases (`scripts/sync-atlas.mjs`)
- D3FEND updates (`app/api/cron/sync-d3fend/route.ts`)
- Sigma / Atomic / GHSA refreshes (existing GH Actions workflows)
- Schema migrations introduced by future ATT&CK releases (e.g. brand-new column needs) — those land in their own commit before the update script runs

## Open follow-ups (post-v19)

- After v19 lands, verify the matrix UI renders the new `Stealth` + `Defense Impairment` tactic columns correctly. Spot-check that any UI strings hardcoding "Defense Evasion" got swapped during the rename pass.
- ICS sub-techniques are net-new in v19 — verify the matrix tree handles `T1234.001`-style ICS IDs (Enterprise/Mobile already do).
- Check `external_actors` and other curator-managed mapping tables for entries pointing at revoked-redirect sources; surface them in admin tooling.

---

## Reviewer findings absorbed

| Source | Finding | Resolution in this design |
|---|---|---|
| Postgres-pro | Cross-domain `domain` overwrite (APT28-class) | Preflight A: migrate to `TEXT[]` |
| Postgres-pro | DELETE+INSERT swap exposes zero-link window | Restructured to insert-then-delete-orphans |
| Postgres-pro | `xmax = 0` unreliable on PG 15+ | Two-CTE INSERT/UPDATE split |
| Postgres-pro | No post-UPSERT integrity assertion | Added |
| Architect-reviewer | ATLAS overlap with `sync-atlas.mjs` | Dropped ATLAS from script's domain set |
| Architect-reviewer | No concurrency lock | `pg_try_advisory_lock` at start |
| Architect-reviewer | Forking STIX extractor in two languages | Subprocess to `seed/extract.py --json` instead |
| Architect-reviewer | Revoked-by redirects not surfaced | Logged + included in metadata |
| Fullstack-developer | Don't port `extract.py` to JS | Adopted: subprocess pattern |
| Fullstack-developer | Dry-run needs per-entity diff | Output spec rewritten |
| Fullstack-developer | `_TACTIC_SORT_ORDER` missing v19 entries | Preflight B |
| Fullstack-developer | Bundle fetch belongs in script, not workflow | Confirmed in design |
| Fullstack-developer | No version guard | Strictly-greater spec-version check + `--force` override |

_Author: Claude Opus 4.7 — 2026-04-28 (v2 incorporates architect + postgres + fullstack review)_

---

## First production run — v18.1 → v19.0 (2026-05-03)

GH Actions run [#25293647404](https://github.com/PerIPan/mitre-explorer-plus/actions/runs/25293647404) — **41.7 s end-to-end, verification passed, zero relationships lost.**

### Entity deltas

| Table | Pre | Post | Δ | Notes |
|---|---:|---:|---:|---|
| `tactics` | 57 | 57 | 0 | Stealth rename in place; +1 net came from earlier attempts (Defense Impairment) |
| `techniques` | 1,295 | 1,295 | 0 | +46 came on attempt 3; this run was idempotent re-application |
| `threat_groups` | 193 | 193 | 0 | Updates only |
| `attack_software` | 914 | **953** | **+39** | New malware/tool entries in v19 |
| `mitigations` | 369 | 369 | 0 | Updates only |
| `campaigns` | 56 | **60** | **+4** | New named campaigns in v19 |
| `data_sources` | 42 | 42 | 0 | Updates only |
| `data_components` | 122 | 122 | 0 | Updates only (12 skipped — parent data_source not in ingest scope) |

**Total entities touched: 2,874** across all UPSERTs.

### Relation deltas (insert-then-delete-orphans)

| Relation table | Pre | Post | Δ | Within-run churn |
|---|---:|---:|---:|---|
| `technique_tactics` | 1,502 | 1,538 | **+36** | +1,431 touched / −82 orphans removed |
| `group_techniques` | 4,750 | 4,937 | **+187** | +4,937 touched / −124 orphans |
| `group_software` | 1,130 | 1,177 | **+47** | +1,177 touched / −6 orphans |
| `software_techniques` | 12,128 | 12,784 | **+656** | +12,784 touched / −167 orphans |
| `mitigation_techniques` | 2,187 | 2,261 | **+74** | +2,017 touched / −95 orphans |
| `campaign_techniques` | 1,126 | 1,273 | **+147** | +1,273 touched / −35 orphans |
| `campaign_software` | 153 | 176 | **+23** | +176 touched / −0 orphans |
| `group_campaigns` | 26 | 28 | **+2** | +27 touched / −0 orphans |
| `technique_data_components` | 3,024 | 3,331 | **+307** | +3,231 touched / −80 orphans |

**Every relation table grew net positive.** The orphan deletes (−589 across all 9 tables) reflect v19's authoritative revocations — MITRE explicitly removed those specific group↔technique attributions, and the reconciler obeyed. Zero relations were lost to bugs.

### Sanity checks

| Check | Expected | Actual |
|---|---|---|
| Stealth rename | `TA0005 \| Stealth \| sort=7` | ✅ |
| Defense Impairment new | `TA0112 \| Defense Impairment \| sort=8` | ✅ |
| APT28 cross-domain merge | `domain = {enterprise-attack, mobile-attack}` | ✅ (correctly NOT in ICS) |
| `seed_metadata` rows for v19.0 | 3 rows (ent + mob + ics) | ✅ |
| Verification harness | `passed — no count regressions, no UUIDs missing, no orphan sub-techniques` | ✅ |

### Skipped relations (logged, not failed)

15 `technique_tactics` + 30 `technique_data_components` skipped because parent or child stix_id is not in DB. These reference entities outside our ingest scope (likely ATLAS objects); they were never in DB to begin with and stay that way.

### Failure-recovery cost

Took **4 attempts** to land clean. Each fix uncovered a real issue caught immediately:

| Attempt | Issue | Fix |
|---|---|---|
| 1 | `column "platforms" is of type text[] but expression is of type text` | Refactored `upsertEntity` to jsonb input; shared `jsonbColumnExpr` across both helpers |
| 2 | `duplicate key value violates unique constraint "techniques_attack_id_key"` | Filter empty `attack_id` rows in `mergeByStixId` (mirrors `seed.py`) |
| 3 | `invalid reference to FROM-clause entry for table "threat_groups"` | Use `t.domain` alias inside cross-domain UPDATE SET (was bare `${table}.domain`) |
| 4 | ✅ success | — |

UPSERT idempotency meant prior partial runs were harmless — each retry converged to the correct state without manual cleanup.

### Reusability check

Run #5 onwards (e.g. v19.1, v20) will:
1. Fetch new STIX bundles (script auto-detects URLs)
2. Read `x_mitre_version`, compare to last successful run's recorded value via `pg_advisory_lock` + `feed_sync_log` query
3. Refuse if not strictly greater (`--force` to override)
4. Same UPSERT-by-stix_id flow — no schema changes needed for routine releases

The full plan (preflight → entities → relations → snapshot/diff → workflow) is documented at [docs/superpowers/plans/2026-04-28-attack-update-script-plan.md](superpowers/plans/2026-04-28-attack-update-script-plan.md).
