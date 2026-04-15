# GHSA + Packages Integration — Implementation Plan

**Spec:** [2026-04-15-ghsa-packages-integration-design.md](../specs/2026-04-15-ghsa-packages-integration-design.md) (v3.1, approved)

**Goal:** Ship GHSA advisories + Packages as first-class entities. New routes, new tables, new ingest, CAPEC bridge extended, A2A skills added.

**Architecture:** Three new Postgres tables + 1 regular view + 1 materialized view. Weekly GitHub Action ingests from GitHub GraphQL. Library-centric Packages parallel the existing vendor-centric Applications.

**Tech stack:** Next.js 15 App Router, TypeScript, TanStack Query, Neon Postgres, GitHub GraphQL.

**Execution:** In-session by Opus. No subagents. Careful pace, type-check + verify between phases, commit at phase boundaries. This plan is a checklist — each item expands into the detailed SQL/code already in the spec.

---

## Pre-flight

- [ ] Confirm `TOKEN_GHSA` secret exists in GitHub repo settings (user confirmed 2026-04-15)
- [ ] Commit outstanding landing-page work from earlier in session (RecentCvesCard + 2-column grid)
- [ ] Commit spec + plan docs

## Phase A — Schema migration

**File:** `scripts/migrate-ghsa.sql`

- [ ] `CREATE EXTENSION IF NOT EXISTS pg_trgm;`
- [ ] `CREATE TABLE ecosystems` + insert 12 rows (idempotent ON CONFLICT DO NOTHING)
- [ ] `CREATE TABLE packages` with `purl`, `last_seen_at`, `(ecosystem, package_name)` unique, trgm GIN index
- [ ] `CREATE TABLE ghsa_advisories` with row_created_at/row_updated_at + upstream_updated_at distinction, FK `cve_id REFERENCES cve_details(cve_id) ON DELETE SET NULL`, partial index on `published_at DESC WHERE withdrawn_at IS NULL`
- [ ] `CREATE TABLE ghsa_weaknesses(ghsa_id, cwe_id)` PK on both, index on cwe_id
- [ ] `CREATE TABLE ghsa_packages` with GENERATED STORED `vulnerable_range_key`, unique index on (ghsa_id, package_id, vulnerable_range_key), CASCADE on package_id
- [ ] `CREATE VIEW unified_weaknesses` — regular view, UNION ALL cve_weaknesses + ghsa_weaknesses
- [ ] `CREATE MATERIALIZED VIEW package_summary` with CTE-based per-package aggregates (INNER JOIN pkg_adv, LEFT JOIN pkg_tech), + 4 indexes
- [ ] `REFRESH MATERIALIZED VIEW package_summary;` (non-concurrent bootstrap)

**Verify:** run migration against Neon; confirm all 5 tables + 1 view + 1 mat view exist; confirm mat view has 0 rows (expected at migration time).

**Commit:** `feat(schema): GHSA + packages tables, unified_weaknesses view, package_summary matview`

## Phase B — Ingest script

**File:** `scripts/sync-ghsa.mjs`

Structure matches `scripts/seed-csf-enrichment.mjs` pattern:

- [ ] Read `TOKEN_GHSA`, exit if missing
- [ ] `SELECT 1` warmup against Neon
- [ ] Pagination loop — `fetch` to GitHub GraphQL, 100 per page, `publishedSince: 2017-01-01`
- [ ] Per-page transaction (BEGIN/COMMIT per page, not per advisory)
- [ ] Per-advisory savepoint for FK violation retry (cve_id → NULL fallback)
- [ ] Normalize severity: MODERATE → MEDIUM; allowlist enforced
- [ ] Normalize ecosystem: lowercase; unknown codes logged + package row skipped
- [ ] Normalize vulnerableRange: empty string → NULL
- [ ] `purlFor(ecosystem, name)` helper with per-ecosystem lookup table (spec §purl)
- [ ] Upsert `packages` with last_seen_at guard
- [ ] Upsert `ghsa_advisories` on ghsa_id
- [ ] Diff-based upsert for ghsa_weaknesses (INSERT+DO NOTHING, then DELETE WHERE cwe_id <> ALL)
- [ ] Diff-based upsert for ghsa_packages (INSERT+DO NOTHING, then DELETE WHERE (package_id, vulnerable_range_key) NOT IN row-constructor set)
- [ ] Rate limit check: inspect X-RateLimit-Remaining / X-RateLimit-Reset headers, sleep if <100
- [ ] After last page: `REFRESH MATERIALIZED VIEW CONCURRENTLY package_summary`
- [ ] Emit summary counts

**Verify:** dry-run against Neon with DATABASE_URL; expect ~13K advisories, ~15K weakness rows, ~50K package-advisory rows, ~25K unique packages. Wall-clock target: 2-3 minutes + 30-90s for mat view refresh.

**Commit:** `feat(ingest): sync-ghsa.mjs pulls GitHub Security Advisories via GraphQL`

## Phase C — Types + hooks

**Files:**
- Modify `src/lib/types.ts`
- Modify `src/hooks/useApi.ts`

- [ ] Add `GhsaEntry` interface (list row shape)
- [ ] Add `GhsaDetail extends GhsaEntry` interface (adds description, CVSS v4, cwes, packages, techniques)
- [ ] Add `PackageDetail` interface
- [ ] Add `CvePackagesResponse` interface
- [ ] Extend existing `CveDetail` with optional `ghsa?: { ghsaId: string; summary: string | null } | null`
- [ ] Add hooks: `useGhsa`, `useGhsaDetail`, `usePackages`, `usePackageDetail`, `useCvePackages` — follow `useCves` / `useCveDetail` pattern (same queryKey/queryFn shape)

**Verify:** `npx tsc --noEmit`

**Commit:** `feat(types): GHSA + Packages TypeScript interfaces and hooks`

## Phase D — API routes

**Files:**
- Create `app/api/v1/ghsa/route.ts` (list)
- Create `app/api/v1/ghsa/[ghsaId]/route.ts` (detail)
- Create `app/api/v1/packages/route.ts` (list from package_summary)
- Create `app/api/v1/packages/[ecosystem]/[nameEncoded]/route.ts` (detail with decodeURIComponent)
- Create `app/api/v1/cves/[cveId]/packages/route.ts` (CVE → packages via GHSA alias)
- Modify `app/api/v1/cves/[cveId]/route.ts` (add minimal `ghsa: { ghsaId, summary }` stub when alias exists)
- Create `app/api/lib/unifiedWeaknesses.ts` (module-level cached `hasUnifiedWeaknessesView` helper)

- [ ] `/api/v1/ghsa` — paginated list; filters: ecosystem, severity, since, q, has_cve, package, include_withdrawn; default WHERE withdrawn_at IS NULL; techniqueCount via unified_weaknesses + capec + techniques (with fallback through helper)
- [ ] `/api/v1/ghsa/[ghsaId]` — detail; always returns advisory regardless of withdrawn status
- [ ] `/api/v1/packages` — reads `package_summary` view directly; ILIKE on package_name uses trgm
- [ ] `/api/v1/packages/[ecosystem]/[nameEncoded]` — decodeURIComponent, join ghsa_advisories + ghsa_packages + unified_weaknesses for linked techniques
- [ ] `/api/v1/cves/[cveId]/packages` — server-side join via ghsa_advisories.cve_id
- [ ] Modify `/api/v1/cves/[cveId]` — add stub; wrap new join in try/catch for pre-migration safety
- [ ] Extend `unified_weaknesses` helper module — export `hasUnifiedWeaknessesView()` with `_unifiedViewExists` process-level cache

**Verify:** `npx tsc --noEmit`; smoke test each route with curl once ingest has run

**Commit:** `feat(api): /ghsa, /packages, /cves/:id/packages routes + CVE detail stub`

## Phase E — List pages

**Files:**
- Create `app/cti/ghsa/page.tsx`
- Create `src/views/GhsaList.tsx`
- Create `app/packages/page.tsx`
- Create `src/views/PackagesList.tsx`

- [ ] `GhsaList` mirrors `CvesList` pattern: PageHeader + filter chips + DataTable
  - Columns: Severity | GHSA ID | CVE alias | Summary | Ecosystems | Package count | CVSS | Published | Techniques
  - Filters: ecosystem, severity, since (default 30d), has_cve, search
- [ ] `PackagesList` mirrors `ApplicationsList` pattern
  - Columns: Ecosystem | Package | Advisories | Severities | Latest | Techniques
  - Filter by ecosystem chip row
  - Search box debounced
  - Rows link to package detail with `encodeURIComponent(packageName)`

**Verify:** `npx tsc --noEmit`; load each page locally; verify first-sync empty state is graceful ("no advisories yet" message)

**Commit:** `feat(ui): GHSA list page and Packages list page`

## Phase F — Detail pages

**Files:**
- Create `app/cti/ghsa/[ghsaId]/page.tsx`
- Create `src/views/GhsaDetail.tsx`
- Create `app/packages/[ecosystem]/[nameEncoded]/page.tsx`
- Create `src/views/PackageDetail.tsx`

- [ ] `GhsaDetail`: header (ghsaId, severity, CVSS, published), withdrawn banner if applicable, description, CWE chips, affected packages table with purl links, linked ATT&CK techniques
- [ ] `PackageDetail`: ecosystem badge + package name + stats, GHSA advisories list with vuln range + fixed version, linked techniques deduped, related CVEs (from advisories with cve_id)

**Verify:** `npx tsc --noEmit`; load one of each; confirm deep-link via URL-encoded name works for `@angular/core`-style names

**Commit:** `feat(ui): GHSA detail and Package detail pages`

## Phase G — Entity-page "Affected Packages" cards

**Files:**
- Modify `src/components/relationships/TechniqueMapView.tsx` (parallel to line ~960)
- Modify `src/components/relationships/OwaspMapView.tsx` (parallel to line ~269)
- Modify `src/views/CveDetail.tsx` (new tab/section alongside Applications)

- [ ] Add API endpoints to back these queries (if not covered by existing detail endpoints):
  - Technique: `GET /api/v1/techniques/:attackId/packages` — packages whose advisories bridge via CWE → CAPEC → this technique (expose via techniqueMapView detail endpoint if one exists, else add dedicated route)
  - OWASP: join through category's CWE set
  - CVE: reuse `/api/v1/cves/:cveId/packages` from Phase D
- [ ] Add "Affected Packages" `MapCard` to each, matching styling of existing "Affected Applications"
- [ ] Chip format: `ecosystem/name (N advisories)` linking to package detail

**Verify:** `npx tsc --noEmit`; eyeball the three entity pages

**Commit:** `feat(ui): Affected Packages cards on Technique/OWASP/CVE views`

## Phase H — CVE detail enrichment card

**File:** Modify `src/views/CveDetail.tsx`

- [ ] Detect `ghsa` stub in CVE detail response; render collapsible "GitHub Advisory" card when present
- [ ] On expand: fire `useGhsaDetail(ghsaId)` — uses TanStack Query, dedupes, cache shared
- [ ] Loading state: `DiamondLoader`; error state: inline message + retry button
- [ ] Show: GHSA ID link, severity, CVSS, summary; expand → full description + packages table

**Verify:** CVE with a known GHSA alias shows the card; CVE without one doesn't

**Commit:** `feat(ui): CVE detail GitHub Advisory enrichment card`

## Phase I — A2A skills

**Files:**
- Modify `public/.well-known/agent-card.json` — kebab-case skill IDs
- Modify `app/api/a2a/route.ts` — snake_case TOOL_DECLARATIONS + handlers

- [ ] `agent-card.json` — add 4 skills: `ghsa-lookup`, `package-vulnerabilities`, `ghsa-search`, `cve-to-packages`; each with description, input schema, example utterance
- [ ] `TOOL_DECLARATIONS` — add 4 declarations: `get_ghsa_detail`, `get_package_vulnerabilities`, `search_ghsa`, `cve_to_packages`; matching Gemini function-call format
- [ ] Dispatcher case branches — each tool calls the corresponding API route internally and formats response

**Verify:** `curl` live `/api/a2a` with a JSON-RPC SendMessage invoking each new skill; verify response format matches existing skills

**Commit:** `feat(a2a): GHSA + Package skills for agent protocol`

## Phase J — Feed Status

**Files:**
- Modify `src/views/FeedStatus.tsx`
- Modify `app/api/v1/frameworks/status/route.ts`

- [ ] Add 3 new `FRAMEWORK_TABLES` entries: `ghsa_advisories`, `ghsa_weaknesses`, `ghsa_packages`
- [ ] Add separate try/catch block in `/frameworks/status` route for GHSA tables (not merged into existing CSF enrichment catch)

**Verify:** Feed Status page shows 3 new cards with live counts after ingest

**Commit:** `feat(feed-status): track GHSA tables`

## Phase K — GitHub Action

**File:** Create `.github/workflows/sync-ghsa.yml`

- [ ] Trigger: `cron: '0 6 * * 1'` (Mondays 06:00 UTC) + `workflow_dispatch`
- [ ] `concurrency: { group: sync-ghsa, cancel-in-progress: false }`
- [ ] Steps: checkout → setup-node → install deps → run `node scripts/sync-ghsa.mjs`
- [ ] Env: `TOKEN_GHSA: ${{ secrets.TOKEN_GHSA }}`, `DATABASE_URL: ${{ secrets.DATABASE_URL }}`
- [ ] Failure notification: default GitHub Action email on failure

**Verify:** trigger manually via `workflow_dispatch`; observe logs

**Commit:** `chore(ci): weekly GHSA sync workflow`

## Phase L — Sidebar nav

**File:** Modify `src/components/layout/Sidebar.tsx`

- [ ] Add `/packages` to `assetsNav` (under Applications)
- [ ] Add `/cti/ghsa` to `ctiNav` (under CVEs, above IOCs)

**Verify:** sidebar renders correctly on desktop + mobile; active-route highlighting works for the new entries

**Commit:** `feat(nav): Packages and GHSA sidebar entries`

## Phase M — Docs

**File:** Modify `docs/feeds_setup.md`

- [ ] Add new section "GitHub Security Advisories (GHSA)" with:
  - Source URL
  - Table list (3 new + 1 matview)
  - Migration command
  - Ingest command
  - First-sync verification checklist: migration ran → ecosystems seeded → `TOKEN_GHSA` set → sync completed → package_summary populated
  - Weekly sync cadence note

**Verify:** doc renders correctly; links work

**Commit:** `docs: GHSA sync feed documentation`

## Post-implementation

- [ ] Run migration against Neon
- [ ] Run first sync manually (`TOKEN_GHSA=... DATABASE_URL=... node scripts/sync-ghsa.mjs`)
- [ ] Verify counts: ghsa_advisories ~13K, ghsa_weaknesses ~15K, ghsa_packages ~50K, packages ~25K, package_summary row count matches active-advisory package count
- [ ] Smoke-test each new page in browser
- [ ] Enable weekly GitHub Action

---

## Verification snippets

**Type check after each phase:**
```bash
npx tsc --noEmit
```

**API smoke tests (after ingest):**
```bash
curl -sS https://mitre-explorer.org/api/v1/ghsa?limit=3 | jq '.data[0]'
curl -sS https://mitre-explorer.org/api/v1/packages?ecosystem=npm&limit=3 | jq
curl -sS "https://mitre-explorer.org/api/v1/packages/npm/log4js-node" | jq '.advisoryCount'
curl -sS https://mitre-explorer.org/api/v1/cves/CVE-2021-44228/packages | jq
```

**A2A smoke test:**
```bash
curl -sS -X POST https://mitre-explorer.org/api/a2a \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"role":"user","parts":[{"type":"text","text":"show vulnerabilities for npm/log4js-node"}]}}}'
```

**DB coverage verification:**
```sql
SELECT COUNT(DISTINCT w.cwe_id) FILTER (WHERE cm.cwe_id IS NULL) AS uncovered_cwes,
       COUNT(DISTINCT w.cwe_id) AS total_cwes
FROM ghsa_weaknesses w
LEFT JOIN capec_mappings cm ON cm.cwe_id = w.cwe_id;
```
If >30% uncovered, consider post-launch CWE→CAPEC expansion.
