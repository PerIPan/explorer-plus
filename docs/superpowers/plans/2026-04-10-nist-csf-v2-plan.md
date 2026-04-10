# NIST CSF v2 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add NIST Cybersecurity Framework v2 as a new framework overlay with 106 subcategories mapped to ATT&CK techniques via CTID direct mappings.

**Architecture:** Two new tables (`csf_subcategories`, `csf_technique_mappings`), one-time seed for 106 subcategories, weekly cron for CTID mappings with transaction-wrapped nuke-and-replace. New CSF entity type (14th) integrated into technique detail, search, 360 explorer, Matrix filter, and force graph. CSF color: indigo `#6366f1`.

**Tech Stack:** Next.js 16 App Router, PostgreSQL (Neon), pg driver, TypeScript, TanStack React Query, Tailwind CSS 4.

**Spec:** `docs/superpowers/specs/2026-04-10-nist-csf-v2-design.md`

---

## Chunk 1: Database Foundation + Seed Data

### Task 1: Create migration file

**Files:**
- Create: `/Users/peripan/dev/mitre/seed/migrate-csf.sql`

- [ ] **Step 1: Create `seed/migrate-csf.sql`**

```sql
-- NIST CSF v2 Integration — additive migration
-- Safe to run multiple times (IF NOT EXISTS throughout)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─── csf_subcategories: 106 rows, static ────────────────────────────────────
CREATE TABLE IF NOT EXISTS csf_subcategories (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  subcategory_id  TEXT NOT NULL,              -- 'PR.AA-01'
  function        TEXT NOT NULL,              -- 'PR'
  function_name   TEXT NOT NULL,              -- 'Protect'
  category_id     TEXT NOT NULL,              -- 'PR.AA'
  category_name   TEXT NOT NULL,              -- 'Identity Management and Access Control'
  name            TEXT NOT NULL,
  description     TEXT,
  version         TEXT NOT NULL DEFAULT '2.0',
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subcategory_id, version)
);

-- CHECK constraints wrapped for idempotency
DO $$ BEGIN
  ALTER TABLE csf_subcategories
    ADD CONSTRAINT chk_csf_subcategory_id_format
    CHECK (subcategory_id ~ '^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}(\.\d{2})?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE csf_subcategories
    ADD CONSTRAINT chk_csf_function
    CHECK (function IN ('GV','ID','PR','DE','RS','RC'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_csf_sub_function ON csf_subcategories(function);
CREATE INDEX IF NOT EXISTS idx_csf_sub_category ON csf_subcategories(category_id);
CREATE INDEX IF NOT EXISTS idx_csf_sub_subcategory_id ON csf_subcategories(subcategory_id);

-- ─── csf_technique_mappings: CTID direct mappings ───────────────────────────
CREATE TABLE IF NOT EXISTS csf_technique_mappings (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  csf_subcategory_uuid UUID NOT NULL REFERENCES csf_subcategories(id) ON DELETE CASCADE,
  subcategory_id       TEXT NOT NULL,              -- denormalized
  technique_id         UUID REFERENCES techniques(id) ON DELETE CASCADE,
  attack_technique_id  TEXT NOT NULL,              -- denormalized
  mapping_source       TEXT NOT NULL DEFAULT 'ctid',
  is_draft             BOOLEAN NOT NULL DEFAULT FALSE,
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (subcategory_id, attack_technique_id)
);

DO $$ BEGIN
  ALTER TABLE csf_technique_mappings
    ADD CONSTRAINT chk_csf_mapping_source
    CHECK (mapping_source IN ('ctid','manual','override'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  ALTER TABLE csf_technique_mappings
    ADD CONSTRAINT chk_csf_attack_technique_id_format
    CHECK (attack_technique_id ~ '^T\d{4}(\.\d{3})?$');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE INDEX IF NOT EXISTS idx_csf_tech_attackid  ON csf_technique_mappings(attack_technique_id);
CREATE INDEX IF NOT EXISTS idx_csf_tech_subcat    ON csf_technique_mappings(subcategory_id);
CREATE INDEX IF NOT EXISTS idx_csf_tech_uuid      ON csf_technique_mappings(csf_subcategory_uuid);
CREATE INDEX IF NOT EXISTS idx_csf_tech_techuuid  ON csf_technique_mappings(technique_id);
```

- [ ] **Step 2: Run migration on production DB**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql "postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" -f /Users/peripan/dev/mitre/seed/migrate-csf.sql
```

Expected: `CREATE EXTENSION`, `CREATE TABLE`, `CREATE INDEX` messages, no errors.

- [ ] **Step 3: Verify tables exist**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql "postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" -c "\d csf_subcategories" -c "\d csf_technique_mappings"
```

- [ ] **Step 4: Commit**

```bash
git add seed/migrate-csf.sql
git commit -m "feat(csf): add migration for csf_subcategories and csf_technique_mappings"
```

---

### Task 2: Create CSF v2 seed data JSON

**Files:**
- Create: `/Users/peripan/dev/mitre/seed/data/csf-v2-subcategories.json`

The 106 CSF v2 subcategories. This is the CSF v2.0 Core from NIST (Feb 2024). Structure:

- [ ] **Step 1: Create the JSON file with all 106 subcategories**

Format:
```json
[
  {
    "subcategory_id": "GV.OC-01",
    "function": "GV",
    "function_name": "Govern",
    "category_id": "GV.OC",
    "category_name": "Organizational Context",
    "name": "The organizational mission is understood and informs cybersecurity risk management",
    "description": "..."
  },
  ...
]
```

The full 106 entries are from NIST CSF v2.0 Core (Feb 26 2024). Functions breakdown:
- **GV (Govern)** — 6 categories, 31 subcategories
- **ID (Identify)** — 3 categories, 21 subcategories
- **PR (Protect)** — 5 categories, 23 subcategories
- **DE (Detect)** — 2 categories, 11 subcategories
- **RS (Respond)** — 4 categories, 13 subcategories
- **RC (Recover)** — 2 categories, 7 subcategories

Source: https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-20/final — download "Core (XLSX)" or parse from the PDF appendix.

Alternative source: CTID's `mappings-explorer` repo ships `nist_csf_framework.json` with the full subcategory list at:
`https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_csf/nist_csf-2.0/9.0/nist_csf_framework.json`

Fetch this file as the source of truth and transform to the flat JSON format above.

- [ ] **Step 2: Verify file has exactly 106 entries**

```bash
cat /Users/peripan/dev/mitre/seed/data/csf-v2-subcategories.json | python3 -c "import json, sys; print(len(json.load(sys.stdin)))"
```
Expected: `106`

- [ ] **Step 3: Commit**

```bash
git add seed/data/csf-v2-subcategories.json
git commit -m "feat(csf): bundle CSF v2 subcategory reference data (106 rows)"
```

---

### Task 3: Create one-time seed script for subcategories

**Files:**
- Create: `/Users/peripan/dev/mitre/seed/seed-csf-subcategories.mjs`

- [ ] **Step 1: Create the seed script**

```javascript
#!/usr/bin/env node
// seed/seed-csf-subcategories.mjs
// One-time seed of CSF v2 subcategories (106 static rows).
// Re-run safely: uses ON CONFLICT DO UPDATE.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import pg from 'pg';

const __dirname = dirname(fileURLToPath(import.meta.url));
const JSON_PATH = resolve(__dirname, 'data/csf-v2-subcategories.json');

const DATABASE_URL = process.env.DATABASE_URL || process.env.POSTGRES_URL;
if (!DATABASE_URL) {
  console.error('DATABASE_URL or POSTGRES_URL required');
  process.exit(1);
}

const subcategories = JSON.parse(readFileSync(JSON_PATH, 'utf8'));
console.log(`Loading ${subcategories.length} CSF v2 subcategories...`);

const client = new pg.Client({ connectionString: DATABASE_URL });
await client.connect();

try {
  await client.query('BEGIN');
  let inserted = 0;
  let updated = 0;

  for (const s of subcategories) {
    const result = await client.query(
      `INSERT INTO csf_subcategories
         (subcategory_id, function, function_name, category_id, category_name, name, description, version)
       VALUES ($1, $2, $3, $4, $5, $6, $7, '2.0')
       ON CONFLICT (subcategory_id, version)
       DO UPDATE SET
         function = EXCLUDED.function,
         function_name = EXCLUDED.function_name,
         category_id = EXCLUDED.category_id,
         category_name = EXCLUDED.category_name,
         name = EXCLUDED.name,
         description = EXCLUDED.description,
         updated_at = NOW()
       RETURNING xmax = 0 AS inserted`,
      [
        s.subcategory_id,
        s.function,
        s.function_name,
        s.category_id,
        s.category_name,
        s.name,
        s.description ?? null,
      ]
    );
    if (result.rows[0].inserted) inserted++;
    else updated++;
  }

  await client.query('COMMIT');
  console.log(`Done. Inserted: ${inserted}, Updated: ${updated}`);
} catch (err) {
  await client.query('ROLLBACK');
  console.error('Seed failed:', err);
  process.exit(1);
} finally {
  await client.end();
}
```

- [ ] **Step 2: Add npm script to package.json**

Modify `package.json` scripts section, add:
```json
"seed:csf": "node seed/seed-csf-subcategories.mjs"
```

- [ ] **Step 3: Run the seed against production**

```bash
DATABASE_URL="postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" npm run seed:csf
```

Expected: `Loading 106 CSF v2 subcategories...` then `Done. Inserted: 106, Updated: 0`

- [ ] **Step 4: Verify row count**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql "postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" -c "SELECT function, COUNT(*) FROM csf_subcategories GROUP BY function ORDER BY function"
```

Expected: 6 rows showing the function distribution (GV=31, ID=21, PR=23, DE=11, RS=13, RC=7)

- [ ] **Step 5: Commit**

```bash
git add seed/seed-csf-subcategories.mjs package.json
git commit -m "feat(csf): seed script for 106 CSF v2 subcategories"
```

---

## Chunk 2: Cron + API Endpoints

### Task 4: Extract FrameworkMapCard shared component

**Files:**
- Create: `/Users/peripan/dev/mitre/src/components/relationships/shared/FrameworkMapCard.tsx`
- Modify: `/Users/peripan/dev/mitre/src/components/relationships/OwaspMapView.tsx`

Architect review said: extract before cloning. This pays back on CSF immediately.

- [ ] **Step 1: Read current OwaspMapView.tsx to identify the MapCard pattern**

```bash
wc -l /Users/peripan/dev/mitre/src/components/relationships/OwaspMapView.tsx
```

- [ ] **Step 2: Create `FrameworkMapCard.tsx` with the shared pattern**

The shared component accepts `{ title, count, defaultOpen?, children }` and handles collapse state + section title with count badge. Exact API to match what OwaspMapView currently uses inline.

```tsx
'use client';
import { useState, type ReactNode } from 'react';
import { Badge } from '../../shared/Badge';

interface FrameworkMapCardProps {
  title: string;
  count?: number;
  badge?: ReactNode;
  defaultOpen?: boolean;
  children: ReactNode;
}

export function FrameworkMapCard({ title, count, badge, defaultOpen = false, children }: FrameworkMapCardProps) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-[var(--hover-subtle)] transition-colors text-left"
      >
        <span className="flex-1 text-sm font-semibold text-[var(--text-primary)]">
          {title}
          {count !== undefined && <span className="ml-2 text-xs text-[var(--text-secondary)] font-normal">({count})</span>}
        </span>
        {badge}
        <svg className={`w-4 h-4 text-[var(--text-secondary)] transition-transform ${open ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-4 py-4 border-t border-[var(--border-color)]">{children}</div>}
    </div>
  );
}
```

- [ ] **Step 3: Refactor OwaspMapView to use FrameworkMapCard**

Find each inline MapCard section (CWEs, Techniques, CVEs, Applications, Related Categories, ATLAS) and wrap with `<FrameworkMapCard title="..." count={n} defaultOpen={...}>`.

- [ ] **Step 4: Verify OWASP map view still renders correctly**

```bash
cd /Users/peripan/dev/mitre && DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack npx next dev -p 3000 &
sleep 6
curl -s "http://localhost:3000/?entity=A01&tab=owasp-map" -o /dev/null -w "%{http_code}\n"
```
Expected: `200`. Then manual verification in browser.

- [ ] **Step 5: Commit**

```bash
git add src/components/relationships/shared/FrameworkMapCard.tsx src/components/relationships/OwaspMapView.tsx
git commit -m "refactor: extract FrameworkMapCard from OwaspMapView for reuse"
```

---

### Task 5: Create sync-csf cron handler

**Files:**
- Create: `/Users/peripan/dev/mitre/app/api/cron/sync-csf/route.ts`
- Modify: `/Users/peripan/dev/mitre/vercel.json`

- [ ] **Step 1: Create the cron handler**

```ts
import { NextRequest, NextResponse } from 'next/server';
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';

export const maxDuration = 300;

const CTID_CSF_URL =
  'https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_csf/nist_csf-2.0/9.0/attack-14.1-enterprise/nist_csf-2.0_attack-14.1-enterprise.json';

interface CtidMapping {
  attack_object_id: string;       // e.g., 'T1078'
  capability_id: string;          // e.g., 'PR.AA-01'
  mapping_type?: string;
  status?: string;
}

interface CtidMappingFile {
  mapping_objects?: CtidMapping[];
  [key: string]: unknown;
}

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Clean up stale "running" entries
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(), error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'csf' AND status = 'running' AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logResult = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('csf', 'running', NOW())
     RETURNING id`,
  );
  const logId = logResult.rows[0].id;

  try {
    // 1. Fetch OUTSIDE transaction
    const resp = await fetch(CTID_CSF_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(30_000),
    });

    if (!resp.ok) {
      throw new Error(`CTID fetch failed: HTTP ${resp.status}`);
    }

    const data = (await resp.json()) as CtidMappingFile;
    const mappings = data.mapping_objects ?? [];

    if (mappings.length === 0) {
      throw new Error('CTID response has no mapping_objects (schema drift?)');
    }

    // Filter + dedupe in memory
    const seen = new Set<string>();
    const validMappings: Array<{ subcategory_id: string; attack_technique_id: string }> = [];
    for (const m of mappings) {
      const sub = m.capability_id;
      const tid = m.attack_object_id;
      if (!sub || !tid) continue;
      if (!/^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}(\.\d{2})?$/.test(sub)) continue;
      if (!/^T\d{4}(\.\d{3})?$/.test(tid)) continue;
      const key = `${sub}|${tid}`;
      if (seen.has(key)) continue;
      seen.add(key);
      validMappings.push({ subcategory_id: sub, attack_technique_id: tid });
    }

    // 2. Transaction: DELETE + bulk INSERT
    await query('BEGIN');
    try {
      await query(`DELETE FROM csf_technique_mappings WHERE mapping_source = 'ctid'`);

      // Lookup map: subcategory_id → csf_subcategories.id (UUID)
      const subResult = await query<{ id: string; subcategory_id: string }>(
        `SELECT id, subcategory_id FROM csf_subcategories WHERE version = '2.0'`,
      );
      const subUuidMap = new Map(subResult.rows.map((r) => [r.subcategory_id, r.id]));

      // Lookup: attack_technique_id → techniques.id (UUID, nullable)
      const techResult = await query<{ id: string; attack_id: string }>(
        `SELECT id, attack_id FROM techniques`,
      );
      const techUuidMap = new Map(techResult.rows.map((r) => [r.attack_id, r.id]));

      let inserted = 0;
      let skipped = 0;
      const CHUNK_SIZE = 500;

      for (let i = 0; i < validMappings.length; i += CHUNK_SIZE) {
        const chunk = validMappings.slice(i, i + CHUNK_SIZE);
        const rows: unknown[] = [];
        const placeholders: string[] = [];

        for (const [idx, m] of chunk.entries()) {
          const subUuid = subUuidMap.get(m.subcategory_id);
          if (!subUuid) { skipped++; continue; }  // subcategory not in our seed
          const techUuid = techUuidMap.get(m.attack_technique_id) ?? null;

          const base = rows.length;
          rows.push(subUuid, m.subcategory_id, techUuid, m.attack_technique_id, 'ctid', false);
          placeholders.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6})`);
        }

        if (placeholders.length === 0) continue;

        const res = await query(
          `INSERT INTO csf_technique_mappings
             (csf_subcategory_uuid, subcategory_id, technique_id, attack_technique_id, mapping_source, is_draft)
           VALUES ${placeholders.join(',')}
           ON CONFLICT (subcategory_id, attack_technique_id) DO NOTHING`,
          rows,
        );
        inserted += res.rowCount ?? 0;
      }

      await query('COMMIT');

      await query(
        `UPDATE feed_sync_log
         SET status = 'success', completed_at = NOW(),
             records_inserted = $1, records_skipped = $2,
             metadata = $3
         WHERE id = $4`,
        [inserted, skipped, JSON.stringify({ totalMappings: validMappings.length }), logId],
      );

      return NextResponse.json({
        ok: true,
        source: 'csf',
        recordsInserted: inserted,
        recordsSkipped: skipped,
        totalValidated: validMappings.length,
      });
    } catch (txErr) {
      await query('ROLLBACK');
      throw txErr;
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('CSF sync error:', err);

    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(), error_message = $1
       WHERE id = $2`,
      [msg, logId],
    );

    return NextResponse.json({ ok: false, error: 'Feed sync failed' }, { status: 500 });
  }
}
```

- [ ] **Step 2: Add cron schedule to vercel.json**

Modify `vercel.json`, add to the crons array:
```json
{ "path": "/api/cron/sync-csf", "schedule": "0 5 * * 1" }
```

- [ ] **Step 3: Test the cron handler locally**

```bash
cd /Users/peripan/dev/mitre
DATABASE_URL=postgresql://postgres@localhost:5432/mitre_attack \
  CRON_SECRET=test \
  npx next dev -p 3000 &
sleep 6
curl -s -H "Authorization: Bearer test" http://localhost:3000/api/cron/sync-csf
```

Expected: JSON with `ok: true, recordsInserted: <nonzero>`. If local DB is empty for techniques, `skipped` may be high — that's fine.

- [ ] **Step 4: Test against production (manually trigger)**

```bash
curl -s -H "Authorization: Bearer $CRON_SECRET" https://mitre-explorer.org/api/cron/sync-csf
```

(Get `CRON_SECRET` from Vercel env vars)

- [ ] **Step 5: Verify mappings in production**

```bash
/Applications/Postgres.app/Contents/Versions/18/bin/psql "postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" -c "SELECT COUNT(*), COUNT(DISTINCT subcategory_id) FROM csf_technique_mappings"
```

- [ ] **Step 6: Commit**

```bash
git add app/api/cron/sync-csf vercel.json
git commit -m "feat(csf): sync-csf cron fetches CTID mappings (weekly Mondays 05:00 UTC)"
```

---

### Task 6: Create CSF list API endpoint

**Files:**
- Create: `/Users/peripan/dev/mitre/app/api/v1/frameworks/csf/route.ts`

- [ ] **Step 1: Create the endpoint**

```ts
import { NextRequest } from 'next/server';
import { query } from '../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;

export async function GET(_req: NextRequest) {
  const result = await query<{
    function: string;
    functionName: string;
    subcategoryId: string;
    categoryId: string;
    categoryName: string;
    name: string;
    description: string | null;
    techniqueCount: string;
  }>(
    `SELECT
       s.function,
       s.function_name       AS "functionName",
       s.subcategory_id      AS "subcategoryId",
       s.category_id         AS "categoryId",
       s.category_name       AS "categoryName",
       s.name,
       s.description,
       COUNT(m.id)           AS "techniqueCount"
     FROM csf_subcategories s
     LEFT JOIN csf_technique_mappings m
       ON m.subcategory_id = s.subcategory_id AND m.is_draft = FALSE
     WHERE s.version = '2.0'
     GROUP BY s.id, s.function, s.function_name, s.subcategory_id, s.category_id, s.category_name, s.name, s.description
     ORDER BY s.function, s.subcategory_id`,
  );

  // Group by function
  const functions: Record<string, { function: string; functionName: string; subcategories: unknown[] }> = {};
  for (const r of result.rows) {
    if (!functions[r.function]) {
      functions[r.function] = { function: r.function, functionName: r.functionName, subcategories: [] };
    }
    functions[r.function].subcategories.push({
      subcategoryId: r.subcategoryId,
      categoryId: r.categoryId,
      categoryName: r.categoryName,
      name: r.name,
      description: r.description,
      techniqueCount: parseInt(r.techniqueCount, 10),
    });
  }

  const data = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'].map((fn) => functions[fn]).filter(Boolean);

  return withCors(jsonResponse({ data, total: result.rows.length }, CACHE_TTL));
}
```

- [ ] **Step 2: Test endpoint**

```bash
curl -s http://localhost:3000/api/v1/frameworks/csf | python3 -m json.tool | head -40
```

Expected: JSON with 6 functions, each with subcategories array. `total: 106`.

- [ ] **Step 3: Commit**

```bash
git add app/api/v1/frameworks/csf/route.ts
git commit -m "feat(csf): GET /api/v1/frameworks/csf list endpoint grouped by function"
```

---

### Task 7: Create CSF subcategory detail API endpoint

**Files:**
- Create: `/Users/peripan/dev/mitre/app/api/v1/frameworks/csf/[subcategoryId]/route.ts`

- [ ] **Step 1: Create the endpoint**

```ts
import { NextRequest } from 'next/server';
import { query } from '../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../lib/cors';

export { OPTIONS };

const CACHE_TTL = 3600;
const CSF_ID_RE = /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}(\.\d{2})?$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ subcategoryId: string }> },
) {
  const { subcategoryId: raw } = await params;
  const subcategoryId = raw.toUpperCase();

  if (!CSF_ID_RE.test(subcategoryId)) {
    return withCors(errorResponse(400, 'Invalid subcategory ID', 'VALIDATION_ERROR'));
  }

  const subResult = await query<{
    subcategoryId: string;
    function: string;
    functionName: string;
    categoryId: string;
    categoryName: string;
    name: string;
    description: string | null;
  }>(
    `SELECT
       subcategory_id  AS "subcategoryId",
       function,
       function_name   AS "functionName",
       category_id     AS "categoryId",
       category_name   AS "categoryName",
       name,
       description
     FROM csf_subcategories
     WHERE subcategory_id = $1 AND version = '2.0'
     LIMIT 1`,
    [subcategoryId],
  );

  if (subResult.rows.length === 0) {
    return withCors(errorResponse(404, 'Subcategory not found', 'NOT_FOUND'));
  }

  const sub = subResult.rows[0];

  const [techniquesResult, relatedResult] = await Promise.all([
    query<{ attackId: string; name: string; tacticName: string | null }>(
      `SELECT DISTINCT
         m.attack_technique_id AS "attackId",
         t.name,
         tac.name              AS "tacticName"
       FROM csf_technique_mappings m
       LEFT JOIN techniques t ON t.id = m.technique_id
       LEFT JOIN technique_tactics tt ON tt.technique_id = t.id
       LEFT JOIN tactics tac ON tac.id = tt.tactic_id
       WHERE m.subcategory_id = $1 AND m.is_draft = FALSE
       ORDER BY m.attack_technique_id`,
      [subcategoryId],
    ),

    query<{ subcategoryId: string; name: string; function: string; sharedCount: string }>(
      `SELECT
         s.subcategory_id   AS "subcategoryId",
         s.name,
         s.function,
         COUNT(*)           AS "sharedCount"
       FROM csf_technique_mappings m2
       JOIN csf_subcategories s ON s.subcategory_id = m2.subcategory_id
       WHERE m2.attack_technique_id IN (
         SELECT attack_technique_id FROM csf_technique_mappings
         WHERE subcategory_id = $1 AND is_draft = FALSE
       )
       AND m2.subcategory_id <> $1
       AND m2.is_draft = FALSE
       GROUP BY s.subcategory_id, s.name, s.function
       HAVING COUNT(*) >= 2
       ORDER BY COUNT(*) DESC, s.subcategory_id
       LIMIT 10`,
      [subcategoryId],
    ),
  ]);

  return withCors(jsonResponse({
    ...sub,
    techniques: techniquesResult.rows,
    relatedSubcategories: relatedResult.rows.map((r) => ({ ...r, sharedCount: parseInt(r.sharedCount, 10) })),
  }, CACHE_TTL));
}
```

- [ ] **Step 2: Test endpoint**

```bash
curl -s http://localhost:3000/api/v1/frameworks/csf/PR.AA-01 | python3 -m json.tool
```

Expected: JSON with subcategory details + techniques array + relatedSubcategories.

- [ ] **Step 3: Test 404 case**

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/api/v1/frameworks/csf/XX.YY-99
```
Expected: `400` (validation error, doesn't match regex — if format is valid but not found, `404`).

- [ ] **Step 4: Commit**

```bash
git add app/api/v1/frameworks/csf/[subcategoryId]/route.ts
git commit -m "feat(csf): GET /api/v1/frameworks/csf/[subcategoryId] detail endpoint"
```

---

### Task 8: Create techniques-only endpoint for Matrix filter

**Files:**
- Create: `/Users/peripan/dev/mitre/app/api/v1/frameworks/csf/[subcategoryId]/techniques/route.ts`

- [ ] **Step 1: Create the endpoint**

```ts
import { NextRequest } from 'next/server';
import { query } from '../../../../../lib/db';
import { jsonResponse, errorResponse } from '../../../../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../../../../lib/cors';

export { OPTIONS };

const CSF_ID_RE = /^(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2}(\.\d{2})?$/;

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ subcategoryId: string }> },
) {
  const { subcategoryId: raw } = await params;
  const subcategoryId = raw.toUpperCase();

  if (!CSF_ID_RE.test(subcategoryId)) {
    return withCors(errorResponse(400, 'Invalid subcategory ID', 'VALIDATION_ERROR'));
  }

  const result = await query<{ attackId: string }>(
    `SELECT DISTINCT attack_technique_id AS "attackId"
     FROM csf_technique_mappings
     WHERE subcategory_id = $1 AND is_draft = FALSE
     ORDER BY attack_technique_id`,
    [subcategoryId],
  );

  return withCors(jsonResponse({ techniques: result.rows }, 3600));
}
```

- [ ] **Step 2: Test endpoint**

```bash
curl -s http://localhost:3000/api/v1/frameworks/csf/PR.AA-01/techniques
```

- [ ] **Step 3: Commit**

```bash
git add app/api/v1/frameworks/csf/[subcategoryId]/techniques/route.ts
git commit -m "feat(csf): techniques-only endpoint for Matrix highlight filter"
```

---

### Task 9: Update technique detail endpoint to include CSF

**Files:**
- Modify: `/Users/peripan/dev/mitre/app/api/v1/frameworks/technique/[attackId]/route.ts`

- [ ] **Step 1: Read current file**

```bash
cat /Users/peripan/dev/mitre/app/api/v1/frameworks/technique/[attackId]/route.ts
```

- [ ] **Step 2: Add CSF query to Promise.all**

Find the existing `Promise.all([...])` block and add a CSF query:

```ts
query<{ subcategoryId: string; name: string; function: string; functionName: string }>(
  `SELECT DISTINCT
     m.subcategory_id  AS "subcategoryId",
     s.name,
     s.function,
     s.function_name   AS "functionName"
   FROM csf_technique_mappings m
   JOIN csf_subcategories s ON s.subcategory_id = m.subcategory_id
   WHERE m.attack_technique_id = $1 AND m.is_draft = FALSE
   ORDER BY m.subcategory_id`,
  [attackId],
),
```

Add `csf` to the response object with the result rows.

- [ ] **Step 3: Test**

```bash
curl -s http://localhost:3000/api/v1/frameworks/technique/T1078 | python3 -m json.tool | head -40
```
Expected: response object now has a `csf` array field.

- [ ] **Step 4: Commit**

```bash
git add app/api/v1/frameworks/technique/[attackId]/route.ts
git commit -m "feat(csf): add CSF subcategories to technique frameworks response"
```

---

### Task 10: Update search endpoint to include CSF

**Files:**
- Modify: `/Users/peripan/dev/mitre/app/api/v1/search/route.ts`

- [ ] **Step 1: Add CSF search branch**

Add a CSF subcategory search alongside the existing OWASP search. Case-insensitive match on `subcategory_id` OR `name`.

```ts
const csfResult = await query<{ subcategoryId: string; name: string; function: string }>(
  `SELECT subcategory_id AS "subcategoryId", name, function
   FROM csf_subcategories
   WHERE version = '2.0'
     AND (UPPER(subcategory_id) = UPPER($1) OR name ILIKE $2)
   ORDER BY subcategory_id
   LIMIT 20`,
  [q, `%${q}%`],
);
```

Add `csf: csfResult.rows` to the response object. Update `total` counter.

- [ ] **Step 2: Test**

```bash
curl -s "http://localhost:3000/api/v1/search?q=PR.AA" | python3 -m json.tool
```

- [ ] **Step 3: Commit**

```bash
git add app/api/v1/search/route.ts
git commit -m "feat(csf): add CSF subcategories to search results"
```

---

### Task 11: Update entities endpoint + frameworks status + by-techniques

**Files:**
- Modify: `/Users/peripan/dev/mitre/app/api/v1/entities/route.ts`
- Modify: `/Users/peripan/dev/mitre/app/api/v1/frameworks/status/route.ts`
- Modify: `/Users/peripan/dev/mitre/app/api/v1/frameworks/by-techniques/route.ts`

- [ ] **Step 1: entities endpoint — add CSF branch**

Follow the existing OWASP pattern — UNION the CSF subcategories into the entity index query so they're findable by `GET /api/v1/entities?q=PR.AA-01`.

- [ ] **Step 2: frameworks/status — add counts**

Add to the counts query:
```ts
query<{ count: string }>(`SELECT COUNT(*) AS count FROM csf_subcategories`),
query<{ count: string }>(`SELECT COUNT(*) AS count FROM csf_technique_mappings`),
```

Add to response: `csf_subcategories: n, csf_technique_mappings: n`

- [ ] **Step 3: frameworks/by-techniques — add CSF aggregate**

This endpoint returns framework stats for a given set of technique IDs (used by sector/actor maps). Add a CSF query that returns subcategories linked to the input techniques.

- [ ] **Step 4: Test each endpoint**

```bash
curl -s "http://localhost:3000/api/v1/entities?q=PR.AA-01"
curl -s "http://localhost:3000/api/v1/frameworks/status"
curl -s -X POST "http://localhost:3000/api/v1/frameworks/by-techniques" -H "Content-Type: application/json" -d '{"techniqueIds":["T1078"]}'
```

- [ ] **Step 5: Commit**

```bash
git add app/api/v1/entities app/api/v1/frameworks/status app/api/v1/frameworks/by-techniques
git commit -m "feat(csf): add CSF to entities, status, by-techniques endpoints"
```

---

## Chunk 3: Frontend Pages + Entity Integration

### Task 12: Add CSF to types + EntityLink config

**Files:**
- Modify: `/Users/peripan/dev/mitre/src/lib/types.ts`
- Modify: `/Users/peripan/dev/mitre/src/components/shared/EntityLink.tsx`

- [ ] **Step 1: Add `'csf'` to EntityType union in types.ts**

```ts
export type EntityType =
  | 'technique' | 'group' | 'software' | 'campaign'
  | 'mitigation' | 'tactic' | 'data-source' | 'sector'
  | 'application' | 'cve' | 'owasp' | 'nist' | 'engage'
  | 'csf';  // NEW

export interface CsfSubcategory {
  subcategoryId: string;
  function: string;
  functionName: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
}
```

Also add `csf?: CsfSubcategory[]` to the `FrameworkData` interface if it exists.

- [ ] **Step 2: Add CSF entity config to EntityLink.tsx**

Find the entity config map/switch and add:
```ts
csf: {
  path: 'frameworks/csf',
  color: '#6366f1',          // indigo
  bg: 'bg-indigo-50 dark:bg-indigo-950',
  border: 'border-indigo-200 dark:border-indigo-800',
  text: 'text-indigo-600 dark:text-indigo-400',
}
```

Also add to MAP_TABS:
```ts
csf: 'csf-map',
```

- [ ] **Step 3: Test compilation**

```bash
cd /Users/peripan/dev/mitre && npx tsc --noEmit 2>&1 | head -10
```
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add src/lib/types.ts src/components/shared/EntityLink.tsx
git commit -m "feat(csf): add csf entity type and EntityLink config"
```

---

### Task 13: Create CsfMapView component

**Files:**
- Create: `/Users/peripan/dev/mitre/src/components/relationships/CsfMapView.tsx`

- [ ] **Step 1: Create the component**

Mirrors the slimmed-down OwaspMapView (no CVEs, no apps — just techniques + related + description).

```tsx
'use client';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { FrameworkMapCard } from './shared/FrameworkMapCard';

interface CsfDetail {
  subcategoryId: string;
  function: string;
  functionName: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
  techniques: Array<{ attackId: string; name: string; tacticName: string | null }>;
  relatedSubcategories: Array<{ subcategoryId: string; name: string; function: string; sharedCount: number }>;
}

export function CsfMapView({ subcategoryId }: { subcategoryId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['csf-detail', subcategoryId],
    queryFn: () => apiFetch<CsfDetail>(`/frameworks/csf/${subcategoryId}`),
    staleTime: 5 * 60 * 1000,
  });

  if (isLoading) return <DiamondLoader text="Loading CSF subcategory..." />;
  if (error || !data) return <div className="text-[var(--accent-orange)]">Failed to load subcategory</div>;

  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3">
        <div className="flex items-center gap-2 mb-2">
          <span className="font-mono text-sm font-bold text-indigo-500">{data.subcategoryId}</span>
          <Badge label={data.functionName} variant="neutral" />
          <span className="text-xs text-[var(--text-secondary)]">{data.categoryName}</span>
        </div>
        <h2 className="text-base font-semibold text-[var(--text-primary)] mb-1">{data.name}</h2>
        {data.description && (
          <p className="text-sm text-[var(--text-secondary)]">{data.description}</p>
        )}
      </div>

      <FrameworkMapCard title="ATT&CK Techniques" count={data.techniques.length} defaultOpen>
        <div className="flex flex-wrap gap-1.5">
          {data.techniques.map((t) => (
            <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
          ))}
        </div>
      </FrameworkMapCard>

      {data.relatedSubcategories.length > 0 && (
        <FrameworkMapCard title="Related CSF Subcategories" count={data.relatedSubcategories.length}>
          <div className="flex flex-wrap gap-1.5">
            {data.relatedSubcategories.map((r) => (
              <a
                key={r.subcategoryId}
                href={`/?entity=${encodeURIComponent(r.subcategoryId)}&tab=csf-map`}
                className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-indigo-500 hover:border-indigo-500 transition-colors"
              >
                {r.subcategoryId} {r.name} ({r.sharedCount})
              </a>
            ))}
          </div>
        </FrameworkMapCard>
      )}

      <a
        href={`/frameworks/csf/${data.subcategoryId}`}
        className="inline-block text-xs text-indigo-500 hover:underline"
      >
        View full CSF page →
      </a>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/components/relationships/CsfMapView.tsx
git commit -m "feat(csf): CsfMapView component for 360 map view"
```

---

### Task 14: Wire CSF into Relationships.tsx + Matrix + SearchBar

**Files:**
- Modify: `/Users/peripan/dev/mitre/src/views/Relationships.tsx`
- Modify: `/Users/peripan/dev/mitre/src/views/Matrix.tsx`
- Modify: `/Users/peripan/dev/mitre/src/components/layout/SearchBar.tsx`
- Modify: `/Users/peripan/dev/mitre/src/components/relationships/RelationshipModel.tsx`

- [ ] **Step 1: Relationships.tsx — add `'csf-map'` tab + CsfMapView**

Find the tab switch (similar to OWASP map handling) and add a case for CSF. Add `'csf-map': 'csf'` to `TAB_TYPE_HINT`. Add `'csf-map'` to the `isNonGraphEntity` check. Skip relationships query for CSF tab.

- [ ] **Step 2: Matrix.tsx — add CSF highlight branch**

In the `highlightData` query, add:
```ts
if (highlightType === 'csf') {
  const d = await apiFetch<{ techniques: Array<{ attackId: string }> }>(`/frameworks/csf/${highlightEntity}/techniques`);
  return d.techniques.map((t) => t.attackId);
}
```

- [ ] **Step 3: SearchBar.tsx — handle CSF results**

In the search results rendering, add CSF to the list (similar to OWASP). Navigate to `/frameworks/csf/${subcategoryId}` on click.

- [ ] **Step 4: RelationshipModel.tsx — add CSF data model node**

Add a new node in the force graph data model diagram with position, color `#6366f1`, label "CSF". Add edges: `csf → technique`. Update the legend.

- [ ] **Step 5: Test compilation**

```bash
npx tsc --noEmit 2>&1 | head -10
```

- [ ] **Step 6: Commit**

```bash
git add src/views/Relationships.tsx src/views/Matrix.tsx src/components/layout/SearchBar.tsx src/components/relationships/RelationshipModel.tsx
git commit -m "feat(csf): integrate CSF into 360 explorer, Matrix filter, SearchBar, data model"
```

---

### Task 15: Add CSF section to Technique detail page

**Files:**
- Modify: `/Users/peripan/dev/mitre/src/views/TechniqueDetail.tsx`

- [ ] **Step 1: Find the Frameworks tab content**

```bash
grep -n "NIST 800-53\|frameworks.nist" /Users/peripan/dev/mitre/src/views/TechniqueDetail.tsx
```

- [ ] **Step 2: Add CSF section after NIST section**

```tsx
{frameworks?.csf && frameworks.csf.length > 0 && (
  <div>
    <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
      NIST CSF v2 ({frameworks.csf.length})
    </h4>
    <div className="flex flex-wrap gap-1.5">
      {frameworks.csf.map((c) => (
        <EntityLink
          key={c.subcategoryId}
          type="csf"
          attackId={c.subcategoryId}
          name={`${c.name} (${c.functionName})`}
          useMap
        />
      ))}
    </div>
  </div>
)}
```

- [ ] **Step 3: Test in browser**

Navigate to `/techniques/T1078` and verify CSF section renders.

- [ ] **Step 4: Commit**

```bash
git add src/views/TechniqueDetail.tsx
git commit -m "feat(csf): show CSF subcategories on technique detail page"
```

---

### Task 16: Create CSF browser view component

**Files:**
- Create: `/Users/peripan/dev/mitre/src/views/CsfFramework.tsx`

- [ ] **Step 1: Create the view**

Flat list per function with search filter + function pills.

```tsx
'use client';
import { useState, useMemo, useEffect } from 'react';
import { useParams } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../lib/api';
import { usePageTitle } from '../hooks/usePageTitle';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { DiamondLoader } from '../components/shared/FoldingDiamond';

interface CsfSubcategory {
  subcategoryId: string;
  categoryId: string;
  categoryName: string;
  name: string;
  description: string | null;
  techniqueCount: number;
}

interface CsfFunctionGroup {
  function: string;
  functionName: string;
  subcategories: CsfSubcategory[];
}

interface CsfDetail extends CsfSubcategory {
  function: string;
  functionName: string;
  techniques: Array<{ attackId: string; name: string; tacticName: string | null }>;
  relatedSubcategories: Array<{ subcategoryId: string; name: string; function: string; sharedCount: number }>;
}

const FUNCTIONS = [
  { id: 'GV', name: 'Govern', color: '#8b5cf6' },
  { id: 'ID', name: 'Identify', color: '#3b82f6' },
  { id: 'PR', name: 'Protect', color: '#10b981' },
  { id: 'DE', name: 'Detect', color: '#f59e0b' },
  { id: 'RS', name: 'Respond', color: '#ef4444' },
  { id: 'RC', name: 'Recover', color: '#6366f1' },
];

export function CsfFramework() {
  const { subcategoryId: urlSubId } = useParams<{ subcategoryId?: string }>();
  const [expanded, setExpanded] = useState<string | null>(urlSubId?.toUpperCase() ?? null);
  const [filter, setFilter] = useState<string>('');
  const [functionFilter, setFunctionFilter] = useState<string | null>(null);

  useEffect(() => {
    if (urlSubId) setExpanded(urlSubId.toUpperCase());
  }, [urlSubId]);

  const { data, isLoading } = useQuery({
    queryKey: ['csf-list'],
    queryFn: () => apiFetch<{ data: CsfFunctionGroup[]; total: number }>('/frameworks/csf'),
  });

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['csf-detail', expanded],
    queryFn: () => apiFetch<CsfDetail>(`/frameworks/csf/${expanded}`),
    enabled: !!expanded,
  });

  const filteredGroups = useMemo(() => {
    const groups = data?.data ?? [];
    const q = filter.toLowerCase();
    return groups
      .filter((g) => !functionFilter || g.function === functionFilter)
      .map((g) => ({
        ...g,
        subcategories: g.subcategories.filter(
          (s) =>
            !filter ||
            s.subcategoryId.toLowerCase().includes(q) ||
            s.name.toLowerCase().includes(q),
        ),
      }))
      .filter((g) => g.subcategories.length > 0);
  }, [data, filter, functionFilter]);

  if (isLoading) return <DiamondLoader text="Loading NIST CSF v2..." />;

  return (
    <div className="space-y-4">
      <PageHeader
        title="NIST CSF v2"
        subtitle="NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques (via CTID direct mappings)"
      />

      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          onClick={() => setFunctionFilter(null)}
          className={`px-3 py-1.5 text-xs rounded-md border ${
            functionFilter === null
              ? 'border-indigo-500 text-indigo-500 bg-indigo-50 dark:bg-indigo-950'
              : 'border-[var(--border-color)] text-[var(--text-secondary)]'
          }`}
        >
          All
        </button>
        {FUNCTIONS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => setFunctionFilter(f.id)}
            className={`px-3 py-1.5 text-xs rounded-md border font-mono ${
              functionFilter === f.id
                ? 'border-indigo-500 text-indigo-500 bg-indigo-50 dark:bg-indigo-950'
                : 'border-[var(--border-color)] text-[var(--text-secondary)]'
            }`}
          >
            {f.id} {f.name}
          </button>
        ))}
        <input
          type="search"
          placeholder="Filter by ID or name..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="ml-auto px-3 py-1.5 text-sm rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] min-w-[200px]"
        />
      </div>

      <div className="space-y-6">
        {filteredGroups.map((group) => (
          <div key={group.function}>
            <h3 className="text-sm font-bold text-indigo-500 uppercase tracking-wider mb-2">
              {group.function} {group.functionName} ({group.subcategories.length})
            </h3>
            <div className="space-y-1">
              {group.subcategories.map((sub) => {
                const isOpen = expanded === sub.subcategoryId;
                return (
                  <div key={sub.subcategoryId} className="border border-[var(--border-color)] rounded-lg overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setExpanded(isOpen ? null : sub.subcategoryId)}
                      className="w-full flex items-center gap-3 px-4 py-2 bg-[var(--surface-card)] hover:bg-[var(--hover-subtle)] text-left"
                    >
                      <span className="font-mono text-xs font-bold text-indigo-500 w-20 shrink-0">{sub.subcategoryId}</span>
                      <span className="flex-1 text-sm text-[var(--text-primary)]">{sub.name}</span>
                      <Badge label={`${sub.techniqueCount} tech`} variant="teal" />
                      <a
                        href={`/?entity=${encodeURIComponent(sub.subcategoryId)}&tab=csf-map`}
                        onClick={(e) => e.stopPropagation()}
                        className="text-[10px] text-indigo-500 hover:underline shrink-0"
                      >
                        360 →
                      </a>
                      <svg className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform ${isOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>
                    {isOpen && (
                      <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3 border-t border-[var(--border-color)]">
                        {detailLoading && expanded === sub.subcategoryId ? (
                          <DiamondLoader text="Loading..." />
                        ) : detail && detail.subcategoryId === sub.subcategoryId ? (
                          <>
                            {detail.description && (
                              <p className="text-sm text-[var(--text-secondary)]">{detail.description}</p>
                            )}
                            {detail.techniques.length > 0 && (
                              <div>
                                <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                                  ATT&CK Techniques ({detail.techniques.length})
                                </h4>
                                <div className="flex flex-wrap gap-1.5">
                                  {detail.techniques.map((t) => (
                                    <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                                  ))}
                                </div>
                              </div>
                            )}
                            {detail.relatedSubcategories.length > 0 && (
                              <div>
                                <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
                                  Related Subcategories
                                </h4>
                                <div className="flex flex-wrap gap-1.5">
                                  {detail.relatedSubcategories.map((r) => (
                                    <button
                                      key={r.subcategoryId}
                                      type="button"
                                      onClick={() => setExpanded(r.subcategoryId)}
                                      className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-indigo-500 hover:border-indigo-500"
                                    >
                                      {r.subcategoryId} ({r.sharedCount})
                                    </button>
                                  ))}
                                </div>
                              </div>
                            )}
                          </>
                        ) : null}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
git add src/views/CsfFramework.tsx
git commit -m "feat(csf): CsfFramework browser view with function filter and search"
```

---

### Task 17: Create CSF Next.js pages

**Files:**
- Create: `/Users/peripan/dev/mitre/app/frameworks/csf/page.tsx`
- Create: `/Users/peripan/dev/mitre/app/frameworks/csf/[subcategoryId]/page.tsx`
- Modify: `/Users/peripan/dev/mitre/app/lib/data.ts`

- [ ] **Step 1: Add fetchCsfSubcategory to app/lib/data.ts**

```ts
export const fetchCsfSubcategory = cache(async (subcategoryId: string) => {
  const result = await query(
    `SELECT subcategory_id, function, function_name, category_id, category_name, name, description
     FROM csf_subcategories
     WHERE subcategory_id = $1 AND version = '2.0'`,
    [subcategoryId.toUpperCase()],
  );
  return result.rows[0] ?? null;
});
```

- [ ] **Step 2: Create `app/frameworks/csf/page.tsx`**

```tsx
import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CsfFramework } from '../../../src/views/CsfFramework';

export const metadata: Metadata = {
  title: 'NIST CSF v2 — MITRE Explorer',
  description: 'NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques. Govern, Identify, Protect, Detect, Respond, Recover.',
  openGraph: {
    title: 'NIST CSF v2 — MITRE Explorer',
    description: 'NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques.',
    url: 'https://mitre-explorer.org/frameworks/csf',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading CSF..." />}>
      <CsfFramework />
    </Suspense>
  );
}
```

- [ ] **Step 3: Create `app/frameworks/csf/[subcategoryId]/page.tsx`**

```tsx
import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchCsfSubcategory } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { CsfFramework } from '../../../../src/views/CsfFramework';

export async function generateMetadata({ params }: { params: Promise<{ subcategoryId: string }> }): Promise<Metadata> {
  const { subcategoryId } = await params;
  const data = await fetchCsfSubcategory(subcategoryId);
  if (!data) return { title: 'Not Found' };
  const title = `${data.subcategory_id} ${data.name}`;
  const description = data.description?.slice(0, 160) ?? `NIST CSF v2 subcategory ${data.subcategory_id}`;
  return {
    title,
    description,
    openGraph: { title, description, url: `https://mitre-explorer.org/frameworks/csf/${data.subcategory_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ subcategoryId: string }> }) {
  const { subcategoryId } = await params;
  const data = await fetchCsfSubcategory(subcategoryId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <CsfFramework />
    </Suspense>
  );
}
```

- [ ] **Step 4: Test build**

```bash
DATABASE_URL="..." npx next build 2>&1 | tail -20
```

- [ ] **Step 5: Test in browser**

```bash
curl -s http://localhost:3000/frameworks/csf -o /dev/null -w "%{http_code}\n"
curl -s http://localhost:3000/frameworks/csf/PR.AA-01 | grep -o '<title>[^<]*</title>'
```

- [ ] **Step 6: Commit**

```bash
git add app/frameworks/csf app/lib/data.ts
git commit -m "feat(csf): Next.js pages for /frameworks/csf + /frameworks/csf/[subcategoryId]"
```

---

### Task 18: Add CSF URLs to sitemap

**Files:**
- Modify: `/Users/peripan/dev/mitre/app/sitemap.ts`

- [ ] **Step 1: Add CSF query**

```ts
const csfResult = await query<{ subcategory_id: string }>(
  'SELECT subcategory_id FROM csf_subcategories WHERE version = $1',
  ['2.0'],
);
```

Add to the promise array. Then build CSF URLs:

```ts
const csfUrls = csfResult.rows.map((r) => ({
  url: `${BASE_URL}/frameworks/csf/${r.subcategory_id}`,
  changeFrequency: 'monthly' as const,
}));
```

Include in the final return. Also add `/frameworks/csf` to the static pages array.

- [ ] **Step 2: Test sitemap**

```bash
curl -s http://localhost:3000/sitemap.xml | grep "frameworks/csf" | head -5
```

- [ ] **Step 3: Commit**

```bash
git add app/sitemap.ts
git commit -m "feat(csf): add CSF subcategory URLs to sitemap (106 entries)"
```

---

## Chunk 4: Verification + Deploy

### Task 19: Full build + TypeScript check

- [ ] **Step 1: TypeScript clean**

```bash
cd /Users/peripan/dev/mitre && npx tsc --noEmit 2>&1 | head -20
```
Expected: zero errors.

- [ ] **Step 2: Next.js build**

```bash
DATABASE_URL="postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?channel_binding=require&sslmode=require" npx next build 2>&1 | tail -40
```
Expected: successful build, `/frameworks/csf` and `/frameworks/csf/[subcategoryId]` in the route list.

- [ ] **Step 3: Check for CSF routes**

The build output should list:
- `/frameworks/csf` (static)
- `/frameworks/csf/[subcategoryId]` (dynamic, ISR)
- `/api/v1/frameworks/csf`
- `/api/v1/frameworks/csf/[subcategoryId]`
- `/api/v1/frameworks/csf/[subcategoryId]/techniques`
- `/api/cron/sync-csf`

---

### Task 20: Playwright E2E verification

- [ ] **Step 1: Start dev server**

```bash
DATABASE_URL="postgresql://neondb_owner:npg_3sOqaxe7kfzQ@..." npx next dev -p 3000 &
sleep 6
```

- [ ] **Step 2: Test pages via curl**

```bash
# List page
curl -s http://localhost:3000/frameworks/csf | grep -o '<title>[^<]*</title>'
# Expected: <title>NIST CSF v2 — MITRE Explorer</title>

# Detail page (after seed + cron run)
curl -s http://localhost:3000/frameworks/csf/PR.AA-01 | grep -o '<title>[^<]*</title>'
# Expected: title with PR.AA-01 name

# API list
curl -s http://localhost:3000/api/v1/frameworks/csf | python3 -c "import json,sys; d=json.load(sys.stdin); print(f\"Functions: {len(d['data'])}, Total: {d['total']}\")"
# Expected: Functions: 6, Total: 106

# Entity search
curl -s "http://localhost:3000/api/v1/entities?q=PR.AA-01" | python3 -m json.tool | head -20

# Technique detail with CSF
curl -s http://localhost:3000/api/v1/frameworks/technique/T1078 | python3 -c "import json,sys; d=json.load(sys.stdin); print('CSF entries:', len(d.get('csf', [])))"
```

- [ ] **Step 3: Navigate via Playwright MCP**

Use Playwright to verify:
1. `https://mitre-explorer.org/frameworks/csf` renders the list
2. Click on `PR.AA-01` expand — see description + techniques
3. Click "360 →" — verify `/?entity=PR.AA-01&tab=csf-map` renders CsfMapView
4. Search "PR.AA-01" in SearchBar — result shows CSF entry
5. Navigate to `/techniques/T1078` — CSF section visible in Frameworks tab
6. Navigate to `/matrix?entity=PR.AA-01&type=csf` — matrix shows highlighted techniques

---

### Task 21: Deploy + production verification

- [ ] **Step 1: Push to main**

```bash
git push origin main
```

- [ ] **Step 2: Wait for Vercel deploy (~90s)**

```bash
sleep 90
```

- [ ] **Step 3: Verify production**

```bash
curl -s https://mitre-explorer.org/frameworks/csf -o /dev/null -w "%{http_code}\n"
# Expected: 200

curl -s https://mitre-explorer.org/api/v1/frameworks/csf | python3 -c "import json,sys; d=json.load(sys.stdin); print(f\"Functions: {len(d['data'])}\")"
# Expected: Functions: 6

curl -s "https://mitre-explorer.org/frameworks/csf/PR.AA-01" | grep -o '<title>[^<]*</title>'

curl -s https://mitre-explorer.org/sitemap.xml | grep -c "frameworks/csf"
# Expected: 107 (1 list page + 106 subcategories)
```

- [ ] **Step 4: Trigger sync-csf cron manually on production**

```bash
curl -s -H "Authorization: Bearer $CRON_SECRET" https://mitre-explorer.org/api/cron/sync-csf
# Expected: { ok: true, recordsInserted: >500 }
```

- [ ] **Step 5: Final commit + tag**

```bash
git tag csf-v2-complete
git push origin csf-v2-complete
```

---

## Unresolved Questions

1. **CTID URL versioning** — the URL in sync-csf uses `nist_csf-2.0/9.0/attack-14.1-enterprise/`. Verify this exact path is correct during implementation (CTID may have reorganized). If 404, try `main/mappings/nist_csf/` and browse the tree.

2. **CSF seed JSON source** — the 106 subcategories need to come from NIST's official CSF v2 Core document. The implementer should either:
   - Fetch from CTID's `nist_csf_framework.json` at install time (bundle the result)
   - Parse from NIST's official CSF v2 Core XLSX/PDF
   - Manually type the 106 entries (tedious but reliable)

3. **CIS Controls table** — noticed `cis_controls` exists during exploration but isn't mentioned in the spec. Confirm it's unrelated to this CSF work (it is — CIS Controls is a separate framework).

4. **FrameworkMapCard migration scope** — Task 4 refactors OwaspMapView but doesn't touch the 6 other MapView files (Actor, Application, DataSource, Mitigation, Sector, Software, Tactic, Technique). Those can migrate opportunistically in follow-up work; not blocking.

5. **Matrix CSF filter UX** — the `/matrix?type=csf-function` for function-level (not subcategory) highlighting requires a separate endpoint `/api/v1/frameworks/csf/functions/[function]/techniques`. Deferred unless user explicitly asks.

---

**Total estimated tasks: 21**
**Total estimated sessions: 4-5**
