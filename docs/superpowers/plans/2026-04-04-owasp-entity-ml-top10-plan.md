# OWASP Entity + ML/LLM Top 10 Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make OWASP a full entity type (searchable, linkable, on technique/CVE pages) and seed ML Top 10 + LLM Top 10 for AI risk coverage.

**Architecture:** Extend `owasp_top10` table with `framework` discriminator + `atlas_technique_ids` array. Web categories bridge to techniques via CWE→CAPEC. ML/LLM categories bridge via ATLAS technique IDs. Frontend gets framework tab bar, EntityType integration, and OWASP sections on existing detail pages.

**Tech Stack:** PostgreSQL (Neon), TypeScript, React, Vercel serverless, @tanstack/react-query

**Spec:** `docs/superpowers/specs/2026-04-04-owasp-entity-ml-top10-design.md`

---

## Phase 1: Database + Seed

### Task 1: Run DB migration

**Files:**
- Create: `scripts/migrate-owasp-framework.sql`

- [ ] **Step 1: Write migration SQL**

```sql
-- scripts/migrate-owasp-framework.sql
BEGIN;

-- Add columns (IF NOT EXISTS for idempotency)
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS framework VARCHAR(50) NOT NULL DEFAULT 'web-2021';
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS atlas_technique_ids TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS is_draft BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE owasp_top10 ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Note: existing rows get framework='web-2021' and updated_at=now() from DEFAULT — no backfill needed

-- Drop old unique constraint (may be constraint or index — try both)
ALTER TABLE owasp_top10 DROP CONSTRAINT IF EXISTS owasp_top10_category_id_key;
DROP INDEX IF EXISTS idx_owasp_top10_category;

-- New composite unique
CREATE UNIQUE INDEX IF NOT EXISTS idx_owasp_category_framework
  ON owasp_top10(category_id, framework);

-- Framework CHECK constraint
DO $$ BEGIN
  ALTER TABLE owasp_top10
    ADD CONSTRAINT chk_owasp_framework
    CHECK (framework IN ('web-2021', 'ml-2023', 'llm-2025'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- GIN indexes for array overlap queries
CREATE INDEX IF NOT EXISTS idx_owasp_cwe_ids_gin ON owasp_top10 USING gin(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_owasp_atlas_ids_gin ON owasp_top10 USING gin(atlas_technique_ids);

-- Text search index for search endpoint
CREATE INDEX IF NOT EXISTS idx_owasp_search_gin
  ON owasp_top10 USING gin(to_tsvector('english', name || ' ' || COALESCE(description, '')));

COMMIT;
```

- [ ] **Step 2: Run migration against Neon**

```bash
PGPASSWORD=npg_3sOqaxe7kfzQ psql "postgresql://neondb_owner@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require" -f scripts/migrate-owasp-framework.sql
```

Expected: `ALTER TABLE`, `UPDATE 10`, `CREATE INDEX` — no errors.

- [ ] **Step 3: Verify schema**

```bash
psql <conn> -c "\d owasp_top10"
```

Expected: `framework`, `atlas_technique_ids`, `is_draft`, `updated_at` columns present.

- [ ] **Step 4: Commit**

```bash
git add scripts/migrate-owasp-framework.sql
git commit -m "feat(db): add framework, atlas_technique_ids, is_draft, updated_at to owasp_top10"
```

---

### Task 2: Seed ML Top 10 + LLM Top 10

**Files:**
- Create: `scripts/seed-owasp-ml-llm.mjs`

- [ ] **Step 1: Write seed script**

Follow the pattern from `scripts/sync-frameworks.mjs` — uses `pg` Pool, supports `DATABASE_URL` env var, handles Neon SSL.

```js
// scripts/seed-owasp-ml-llm.mjs
import pg from 'pg';
const { Pool } = pg;

const connectionString = process.env.DATABASE_URL;
if (!connectionString) { console.error('DATABASE_URL required'); process.exit(1); }

const isProduction = connectionString.includes('neon') || connectionString.includes('vercel');
const pool = new Pool({
  connectionString,
  max: 1,
  ssl: isProduction ? { rejectUnauthorized: true } : undefined,
});

const ML_TOP10 = [
  { id: 'ML01', name: 'Input Manipulation Attack', desc: 'Adversarial inputs cause model to produce incorrect predictions.', url: 'https://mltop10.info/', atlas: ['AML.T0043'], cwes: ['CWE-20'], draft: true },
  { id: 'ML02', name: 'Data Poisoning Attack', desc: 'Attacker injects malicious data into training set to corrupt model behavior.', url: 'https://mltop10.info/', atlas: ['AML.T0020'], cwes: ['CWE-506'], draft: true },
  { id: 'ML03', name: 'Model Inversion Attack', desc: 'Attacker reconstructs sensitive training data by querying the model.', url: 'https://mltop10.info/', atlas: ['AML.T0024'], cwes: [], draft: true },
  { id: 'ML04', name: 'Membership Inference Attack', desc: 'Attacker determines whether a specific record was in the training set.', url: 'https://mltop10.info/', atlas: ['AML.T0025'], cwes: [], draft: true },
  { id: 'ML05', name: 'Model Theft', desc: 'Model functionality extracted via repeated queries.', url: 'https://mltop10.info/', atlas: ['AML.T0044'], cwes: [], draft: true },
  { id: 'ML06', name: 'AI Supply Chain Attacks', desc: 'Compromise of upstream datasets, pretrained models, or ML tooling dependencies.', url: 'https://mltop10.info/', atlas: ['AML.T0010'], cwes: ['CWE-1357'], draft: true },
  { id: 'ML07', name: 'Transfer Learning Attack', desc: 'Malicious pretrained model introduces backdoors when fine-tuned downstream.', url: 'https://mltop10.info/', atlas: ['AML.T0019'], cwes: [], draft: true },
  { id: 'ML08', name: 'Model Skewing', desc: 'Attacker feeds live feedback to shift model behavior over time.', url: 'https://mltop10.info/', atlas: ['AML.T0031'], cwes: [], draft: true },
  { id: 'ML09', name: 'Output Integrity Attack', desc: 'Model outputs are tampered with post-inference before reaching the consumer.', url: 'https://mltop10.info/', atlas: ['AML.T0047'], cwes: ['CWE-345'], draft: true },
  { id: 'ML10', name: 'Model Poisoning', desc: 'Attacker directly modifies model weights or serialized model artifacts.', url: 'https://mltop10.info/', atlas: ['AML.T0018'], cwes: ['CWE-506'], draft: true },
];

const LLM_TOP10 = [
  { id: 'LLM01', name: 'Prompt Injection', desc: 'User or retrieved content overrides system instructions or exfiltrates data.', url: 'https://genai.owasp.org/llmrisk/llm01-prompt-injection/', atlas: ['AML.T0051'], cwes: ['CWE-1352', 'CWE-74'], draft: false },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', desc: 'Model leaks PII, credentials, or secrets through responses or logs.', url: 'https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/', atlas: ['AML.T0024', 'AML.T0025'], cwes: ['CWE-200', 'CWE-359'], draft: false },
  { id: 'LLM03', name: 'Supply Chain', desc: 'Compromised datasets, model providers, or plugins introduce backdoors.', url: 'https://genai.owasp.org/llmrisk/llm03-supply-chain/', atlas: ['AML.T0010'], cwes: ['CWE-1357'], draft: false },
  { id: 'LLM04', name: 'Data and Model Poisoning', desc: 'Training, fine-tuning, or RAG corpus manipulation changes model behavior.', url: 'https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/', atlas: ['AML.T0020', 'AML.T0018'], cwes: ['CWE-506'], draft: false },
  { id: 'LLM05', name: 'Improper Output Handling', desc: 'LLM outputs passed to downstream systems without sanitization.', url: 'https://genai.owasp.org/llmrisk/llm05-improper-output-handling/', atlas: [], cwes: ['CWE-116', 'CWE-79'], draft: false },
  { id: 'LLM06', name: 'Excessive Agency', desc: 'LLM agents granted overly broad permissions to act on external systems.', url: 'https://genai.owasp.org/llmrisk/llm06-excessive-agency/', atlas: [], cwes: ['CWE-250', 'CWE-269'], draft: false },
  { id: 'LLM07', name: 'System Prompt Leakage', desc: 'Internal system prompts containing secrets or logic are extracted by users.', url: 'https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/', atlas: ['AML.T0024'], cwes: ['CWE-200'], draft: false },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', desc: 'RAG vector stores become injection or data leakage attack surface.', url: 'https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/', atlas: ['AML.T0020'], cwes: [], draft: false },
  { id: 'LLM09', name: 'Misinformation', desc: 'Model confidently generates false content causing harm or fraud.', url: 'https://genai.owasp.org/llmrisk/llm09-misinformation/', atlas: ['AML.T0048'], cwes: [], draft: false },
  { id: 'LLM10', name: 'Unbounded Consumption', desc: 'Uncontrolled inference cost or latency via abuse or missing rate limits.', url: 'https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/', atlas: [], cwes: ['CWE-400', 'CWE-770'], draft: false },
];

async function seed() {
  const client = await pool.connect();
  try {
    // Guard: verify migration ran (framework column must exist)
    const colCheck = await client.query(
      `SELECT 1 FROM information_schema.columns WHERE table_name='owasp_top10' AND column_name='framework'`
    );
    if (colCheck.rows.length === 0) {
      console.error('ERROR: migration not applied — run scripts/migrate-owasp-framework.sql first');
      process.exit(1);
    }

    await client.query('BEGIN');

    const upsertSQL = `
      INSERT INTO owasp_top10 (category_id, name, description, url, cwe_ids, framework, atlas_technique_ids, is_draft, updated_at)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
      ON CONFLICT (category_id, framework) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        url = EXCLUDED.url,
        cwe_ids = EXCLUDED.cwe_ids,
        atlas_technique_ids = EXCLUDED.atlas_technique_ids,
        is_draft = EXCLUDED.is_draft,
        updated_at = now()
    `;

    for (const item of ML_TOP10) {
      await client.query(upsertSQL, [item.id, item.name, item.desc, item.url, item.cwes, 'ml-2023', item.atlas, item.draft]);
    }
    console.log(`  ✓ ML Top 10: ${ML_TOP10.length} categories`);

    for (const item of LLM_TOP10) {
      await client.query(upsertSQL, [item.id, item.name, item.desc, item.url, item.cwes, 'llm-2025', item.atlas, item.draft]);
    }
    console.log(`  ✓ LLM Top 10: ${LLM_TOP10.length} categories`);

    await client.query('COMMIT');
    console.log('Done. Cache TTL is 3600s — data visible within 1 hour.');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
    await pool.end();
  }
}

seed().catch((err) => { console.error(err); process.exit(1); });
```

- [ ] **Step 2: Run seed against Neon**

```bash
DATABASE_URL="postgresql://neondb_owner:npg_3sOqaxe7kfzQ@ep-silent-sea-al661u2n-pooler.c-3.eu-central-1.aws.neon.tech/neondb?sslmode=require" node scripts/seed-owasp-ml-llm.mjs
```

Expected: `✓ ML Top 10: 10 categories`, `✓ LLM Top 10: 10 categories`.

- [ ] **Step 3: Verify data**

```bash
psql <conn> -c "SELECT framework, COUNT(*) FROM owasp_top10 GROUP BY framework ORDER BY framework;"
```

Expected: `llm-2025 | 10`, `ml-2023 | 10`, `web-2021 | 10`.

- [ ] **Step 4: Commit**

```bash
git add scripts/seed-owasp-ml-llm.mjs
git commit -m "feat(seed): add OWASP ML Top 10 + LLM Top 10 seed script"
```

---

## Phase 2: API Layer

### Task 3: Update list endpoint (`GET /frameworks/owasp`)

**Files:**
- Modify: `api/v1/frameworks/owasp.ts`

- [ ] **Step 1: Rewrite handler with framework filter + CTE query**

Replace the handler in `api/v1/frameworks/owasp.ts` with:

```ts
import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';

const VALID_FRAMEWORKS = ['web-2021', 'ml-2023', 'llm-2025'];

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const fw = Array.isArray(req.query.framework) ? req.query.framework[0] : req.query.framework;
  const frameworkFilter = fw && VALID_FRAMEWORKS.includes(fw) ? fw : null;

  const result = await query<{
    category_id: string; name: string; description: string | null;
    url: string | null; cwe_ids: string[]; framework: string;
    atlas_technique_ids: string[]; is_draft: boolean;
    technique_count: string; cve_count: string;
  }>(
    `WITH counts AS (
       SELECT o.id,
         (SELECT COUNT(DISTINCT cm.attack_technique_id)
          FROM capec_mappings cm
          WHERE cm.technique_id IS NOT NULL AND cm.cwe_id = ANY(o.cwe_ids))::text AS technique_count,
         (SELECT COUNT(DISTINCT cw.cve_id)
          FROM cve_weaknesses cw
          WHERE cw.cwe_id = ANY(o.cwe_ids))::text AS cve_count
       FROM owasp_top10 o
     )
     SELECT o.category_id, o.name, o.description, o.url, o.cwe_ids,
            o.framework, o.atlas_technique_ids, o.is_draft,
            c.technique_count, c.cve_count
     FROM owasp_top10 o
     JOIN counts c ON c.id = o.id
     ${frameworkFilter ? 'WHERE o.framework = $1' : ''}
     ORDER BY o.framework, o.category_id`,
    frameworkFilter ? [frameworkFilter] : [],
  );

  const data = result.rows.map((r) => ({
    categoryId: r.category_id,
    name: r.name,
    description: r.description,
    url: r.url,
    framework: r.framework,
    isDraft: r.is_draft,
    cweCount: r.cwe_ids.length,
    techniqueCount: parseInt(r.technique_count, 10),
    atlasCount: r.atlas_technique_ids.length,
    cveCount: parseInt(r.cve_count, 10),
  }));

  const frameworks = [...new Set(result.rows.map((r) => r.framework))].sort();
  res.status(200).json({ data, frameworks });
}

export default withHandler(handler, { cacheTtl: 3600 });
```

- [ ] **Step 2: Test locally**

```bash
curl http://localhost:3000/api/v1/frameworks/owasp | jq '.frameworks'
# Expected: ["llm-2025", "ml-2023", "web-2021"]

curl "http://localhost:3000/api/v1/frameworks/owasp?framework=ml-2023" | jq '.data | length'
# Expected: 10
```

- [ ] **Step 3: Commit**

```bash
git add api/v1/frameworks/owasp.ts
git commit -m "feat(api): add framework filter + CTE query to OWASP list endpoint"
```

---

### Task 4: Update detail endpoint (`GET /frameworks/owasp/:categoryId`)

**Files:**
- Modify: `api/v1/frameworks/owasp/[categoryId].ts`

- [ ] **Step 1: Extend validation and add ATLAS + cross-framework lookups**

Key changes to `api/v1/frameworks/owasp/[categoryId].ts`:

1. Change validation regex from `/^A\d{2}$/` to `/^(A|ML|LLM)\d{2}$/i`
2. Add ATLAS techniques query:
   ```sql
   SELECT attack_id AS "attackId", name
   FROM techniques
   WHERE attack_id = ANY($1) AND domain = 'atlas-attack'
   ORDER BY attack_id
   ```
   Param: `cat.atlas_technique_ids`
3. Add related categories query:
   ```sql
   SELECT category_id AS "categoryId", name, framework
   FROM owasp_top10
   WHERE category_id != $1 AND framework != $2
     AND (cwe_ids && $3 OR atlas_technique_ids && $4)
   ORDER BY framework, category_id
   ```
4. Add to response: `framework`, `isDraft`, `atlasTechniques`, `relatedCategories`
5. Read `framework` and `atlas_technique_ids` from the category row

- [ ] **Step 2: Test locally**

```bash
curl http://localhost:3000/api/v1/frameworks/owasp/ML01 | jq '.atlasTechniques'
# Expected: [{"attackId": "AML.T0043", "name": "Craft Adversarial Data"}]

curl http://localhost:3000/api/v1/frameworks/owasp/LLM03 | jq '.relatedCategories'
# Expected: includes ML06 (shared CWE-1357)
```

- [ ] **Step 3: Commit**

```bash
git add api/v1/frameworks/owasp/[categoryId].ts
git commit -m "feat(api): extend OWASP detail for ML/LLM + ATLAS + cross-framework"
```

---

### Task 5: Add OWASP to frameworks/technique endpoint

**Files:**
- Modify: `api/v1/frameworks/technique/[attackId].ts`

- [ ] **Step 1: Add OWASP query to the Promise.all**

Add a 5th query to the existing `Promise.all` in `api/v1/frameworks/technique/[attackId].ts:14`:

```ts
// OWASP categories via CWE overlap (for ATT&CK techniques)
query<{ categoryId: string; name: string; framework: string }>(
  `SELECT DISTINCT o.category_id AS "categoryId", o.name, o.framework
   FROM owasp_top10 o
   JOIN capec_mappings cm ON cm.cwe_id = ANY(o.cwe_ids)
   WHERE cm.attack_technique_id = $1 AND cm.technique_id IS NOT NULL
   ORDER BY o.framework, o.category_id`,
  [attackId],
),
// OWASP categories via ATLAS (for ATLAS techniques)
query<{ categoryId: string; name: string; framework: string }>(
  `SELECT category_id AS "categoryId", name, framework
   FROM owasp_top10
   WHERE $1 = ANY(atlas_technique_ids)
   ORDER BY framework, category_id`,
  [attackId],
),
```

- [ ] **Step 2: Merge results + add to response**

```ts
const owaspRows = [...owaspCweResult.rows, ...owaspAtlasResult.rows];
// Deduplicate by categoryId + framework
const owaspMap = new Map(owaspRows.map(r => [`${r.categoryId}-${r.framework}`, r]));
const owasp = [...owaspMap.values()];
```

Add `owasp` to the response JSON at line 80.

- [ ] **Step 3: Test locally**

```bash
curl http://localhost:3000/api/v1/frameworks/technique/T1059 | jq '.owasp'
# Expected: array with A03 Injection (web-2021) if T1059 maps via CAPEC/CWE

curl http://localhost:3000/api/v1/frameworks/technique/AML.T0043 | jq '.owasp'
# Expected: [{categoryId: "ML01", name: "Input Manipulation Attack", framework: "ml-2023"}]
```

- [ ] **Step 4: Commit**

```bash
git add api/v1/frameworks/technique/[attackId].ts
git commit -m "feat(api): add OWASP categories to technique frameworks endpoint"
```

---

### Task 6: Add OWASP to search endpoint

**Files:**
- Modify: `api/v1/search.ts`

- [ ] **Step 1: Add OWASP query to Promise.all**

Add after the data_sources query (line ~73) in `api/v1/search.ts`:

```ts
// OWASP categories — not domain-filtered
// Matches by full-text on name/description OR exact category_id (case-insensitive)
query<{ categoryId: string; name: string; framework: string; isDraft: boolean }>(
  `SELECT category_id AS "categoryId", name, framework, is_draft AS "isDraft"
   FROM owasp_top10
   WHERE to_tsvector('english', name || ' ' || COALESCE(description, '')) @@ plainto_tsquery('english', $1)
      OR UPPER(category_id) = UPPER($1)
   ORDER BY framework, category_id LIMIT 20`,
  [q],
),
```

- [ ] **Step 2: Add to response**

```ts
owasp: owaspResult.rows,
```

- [ ] **Step 3: Commit**

```bash
git add api/v1/search.ts
git commit -m "feat(api): add OWASP categories to search results"
```

---

### Task 7: Update A2A handler

**Files:**
- Modify: `api/a2a/index.ts`
- Modify: `public/.well-known/agent-card.json`
- Modify: `public/.well-known/agent.json`

- [ ] **Step 1: Update tool definitions (line ~360-377)**

```ts
{
  name: 'get_owasp_top10',
  description: 'Get OWASP Top 10 categories for Web (2021), ML (2023), and LLM (2025) with CWE counts, technique counts, ATLAS counts, and CVE counts.',
  parameters: {
    type: "OBJECT",
    properties: {
      framework: { type: "STRING", description: 'Filter by framework: web-2021, ml-2023, or llm-2025. Omit for all.' },
    },
  },
},
{
  name: 'get_owasp_category',
  description: 'Get details for a specific OWASP category: CWEs, ATT&CK techniques, ATLAS techniques, top CVEs, affected applications, and related categories across frameworks.',
  parameters: {
    type: "OBJECT",
    properties: {
      category_id: { type: "STRING", description: 'OWASP category ID: A01-A10 (Web), ML01-ML10, or LLM01-LLM10' },
    },
    required: ['category_id'],
  },
},
```

- [ ] **Step 2: Update handler dispatch (line ~641-648)**

```ts
case 'get_owasp_top10': {
  const fw = args.framework ? String(args.framework) : '';
  const qs = fw ? `?framework=${encodeURIComponent(fw)}` : '';
  return callInternalApi(`/frameworks/owasp${qs}`);
}
case 'get_owasp_category': {
  const cat = String(args.category_id ?? '').toUpperCase();
  if (!/^(A|ML|LLM)\d{2}$/.test(cat)) return { error: 'Invalid category ID (A01-A10, ML01-ML10, LLM01-LLM10)' };
  return callInternalApi(`/frameworks/owasp/${cat}`);
}
```

- [ ] **Step 3: Update system prompt (line ~383)**

Add to the tool selection rules:
```
- For OWASP categories: use get_owasp_top10 (optionally filtered by framework: web-2021, ml-2023, llm-2025), then get_owasp_category for details
- OWASP links: [A01 Broken Access Control](https://mitre-explorer.org/frameworks/owasp/A01)
```

- [ ] **Step 4: Update agent-card.json skill**

Update the `owasp-top10` skill in `public/.well-known/agent-card.json:200-210`:
```json
{
  "id": "owasp-top10",
  "name": "OWASP Top 10 Analysis",
  "description": "Get OWASP Top 10 categories for Web (2021), ML (2023), and LLM (2025) security risks mapped to ATT&CK + ATLAS techniques via CWE.",
  "examples": [
    "Show me the OWASP Top 10 categories",
    "What techniques relate to OWASP A01 Broken Access Control?",
    "Show me the ML Top 10 AI security risks",
    "Which ATLAS techniques map to LLM01 Prompt Injection?",
    "Compare Web and LLM OWASP supply chain risks"
  ],
  "tags": ["owasp", "top10", "web-security", "appsec", "compliance", "ml-security", "llm-security", "ai-risks"]
}
```

- [ ] **Step 5: Commit**

```bash
git add api/a2a/index.ts public/.well-known/agent-card.json public/.well-known/agent.json
git commit -m "feat(a2a): update OWASP skills for ML/LLM Top 10"
```

---

## Phase 3: Frontend — Types + EntityLink

> **Ordering constraint:** Tasks 8, 9, and 14 must be committed together or in rapid sequence. Adding `'owasp'` to `EntityType` (Task 8) without updating the exhaustive `Record<EntityType, ...>` maps in `EntityLink.tsx` (Task 9) and `Search.tsx` (Task 14) will break TypeScript compilation. Recommended: do all three tasks, then commit once.

### Task 8: Update TypeScript types

**Files:**
- Modify: `src/lib/types.ts:289-296`

- [ ] **Step 1: Add 'owasp' to EntityType union**

At `src/lib/types.ts:289`:

```ts
export type EntityType =
  | 'technique'
  | 'group'
  | 'software'
  | 'campaign'
  | 'mitigation'
  | 'data_source'
  | 'tactic'
  | 'owasp';
```

- [ ] **Step 2: Add OwaspCategory interface**

After the `EntityType` definition, add:

```ts
export interface OwaspCategory {
  categoryId: string;
  name: string;
  description: string | null;
  url: string | null;
  framework: string;
  isDraft: boolean;
  cweCount: number;
  techniqueCount: number;
  atlasCount: number;
  cveCount: number;
}
```

- [ ] **Step 3: Add OwaspSearchResult + owasp to SearchResponse**

The search query only returns `categoryId, name, framework, isDraft` — not the full `OwaspCategory` with counts. Use a narrower type.

At `src/lib/types.ts:195-203`:

```ts
export interface OwaspSearchResult {
  categoryId: string;
  name: string;
  framework: string;
  isDraft: boolean;
}

export interface SearchResponse {
  techniques: Technique[];
  groups: Group[];
  software: Software[];
  mitigations: Mitigation[];
  campaigns: Campaign[];
  data_sources: DataSource[];
  owasp: OwaspSearchResult[];
}
```

- [ ] **Step 4: Add owasp to FrameworkData**

At `src/lib/types.ts:353-359`, add:

```ts
export interface FrameworkData {
  attackId: string;
  nist: NistControl[];
  engage: EngageMapping[];
  verisCategories?: VerisMapping[];
  cloudControls?: CloudControl[];
  owasp?: Array<{ categoryId: string; name: string; framework: string }>;
}
```

- [ ] **Step 5: Commit**

```bash
git add src/lib/types.ts
git commit -m "feat(types): add owasp to EntityType, SearchResponse, FrameworkData"
```

---

### Task 9: Update EntityLink component

**Important:** `entityConfig` and `MAP_TABS` are both `Record<EntityType, ...>` — TypeScript requires every union member present. Adding `'owasp'` to `EntityType` (Task 8) without updating these maps causes compile errors. Tasks 8 and 9 must be committed together or in sequence.

**Decision:** Keep `attackId` prop as-is (no rename). OWASP categories pass `categoryId` into the `attackId` prop — it's a semantic mismatch but not a bug and avoids touching every call site.

**Files:**
- Modify: `src/components/shared/EntityLink.tsx`

- [ ] **Step 1: Add owasp to entityConfig (after line 54)**

```ts
owasp: {
  color: 'text-[var(--accent-orange)]',
  bg: 'bg-[var(--orange-faint)]',
  border: 'border-[var(--orange-dim)]',
  path: 'frameworks/owasp',
},
```

- [ ] **Step 2: Add owasp to MAP_TABS (after line 71)**

Both `entityConfig` and `MAP_TABS` are exhaustive `Record<EntityType, string>` — missing `owasp` will fail TypeScript compilation.

```ts
owasp: 'technique-map', // fallback — no dedicated OWASP 360 view yet
```

- [ ] **Step 3: Commit**

```bash
git add src/components/shared/EntityLink.tsx
git commit -m "feat(ui): add owasp to EntityLink config and MAP_TABS"
```

---

### Task 10: Add OWASP to export pipeline

**Files:**
- Modify: `api/v1/lib/validate.ts:47-56`
- Modify: `api/v1/export/[entityType].ts:22-46`

- [ ] **Step 1: Add 'owasp' to exportSchema entityType enum**

In `api/v1/lib/validate.ts:47`:

```ts
export const exportSchema = z.object({
  entityType: z.enum([
    'techniques',
    'groups',
    'software',
    'mitigations',
    'campaigns',
    'data_sources',
    'tactics',
    'sectors',
    'owasp',
  ]),
  format: z.enum(['csv', 'json']).default('json'),
});
```

- [ ] **Step 2: Add OWASP SQL to ENTITY_QUERIES**

In `api/v1/export/[entityType].ts:22`, add to the `ENTITY_QUERIES` map:

```ts
owasp: `
  SELECT category_id, name, description, url, framework, cwe_ids, atlas_technique_ids, is_draft
  FROM owasp_top10 ORDER BY framework, category_id ASC LIMIT 10000`,
```

- [ ] **Step 3: Update error message (line 56)**

Add `owasp` to the allowed list in the error string.

- [ ] **Step 4: Commit**

```bash
git add api/v1/lib/validate.ts api/v1/export/[entityType].ts
git commit -m "feat(api): add owasp to export pipeline"
```

---

## Phase 4: Frontend — Pages + Integration

### Task 11: Update OWASP page with framework tabs

**Files:**
- Modify: `src/pages/OwaspTop10.tsx`

- [ ] **Step 1: Add framework state + tab bar**

Key changes:
1. Add `framework` state: `const [framework, setFramework] = useState<string | null>(null);`
2. Update query to include framework in **both** the query key and the fetch:
   ```ts
   const { data, isLoading } = useQuery({
     queryKey: ['owasp-top10', framework],
     queryFn: () => apiFetch<{ data: OwaspCategory[]; frameworks: string[] }>(
       '/frameworks/owasp' + (framework ? `?framework=${framework}` : '')
     ),
   });
   ```
3. Add tab bar above categories:
   ```tsx
   <div className="flex gap-2">
     {[null, 'web-2021', 'ml-2023', 'llm-2025'].map(fw => (
       <button key={fw ?? 'all'}
         onClick={() => setFramework(fw)}
         className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
           framework === fw
             ? 'border-[var(--accent-teal)] text-[var(--accent-teal)] bg-[var(--teal-ghost)]'
             : 'border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]'
         }`}
       >
         {fw === null ? 'All' : fw === 'web-2021' ? 'Web (2021)' : fw === 'ml-2023' ? 'ML (2023)' : 'LLM (2025)'}
       </button>
     ))}
   </div>
   ```
4. Show `isDraft` badge: `{cat.isDraft && <Badge label="DRAFT" variant="neutral" />}`
5. Show ATLAS count: `<Badge label={\`${cat.atlasCount} ATLAS\`} variant="purple" />`
6. Update page title dynamically
7. Update detail expansion to show ATLAS techniques + related categories
8. Add **mapping confidence tooltip** per framework. In the expanded detail, after the CWE section, add:
   ```tsx
   {(cat.framework === 'ml-2023' || cat.framework === 'llm-2025') && (
     <span
       className="text-[10px] text-[var(--text-secondary)] italic cursor-help"
       title="CWE mappings are community-contributed, not OWASP-official"
     >
       Community-mapped CWEs
     </span>
   )}
   ```

- [ ] **Step 2: Test locally** — verify tabs filter, DRAFT badge shows on ML, ATLAS counts show

- [ ] **Step 3: Commit**

```bash
git add src/pages/OwaspTop10.tsx
git commit -m "feat(ui): OWASP page framework tabs, DRAFT badges, ATLAS counts"
```

---

### Task 12: Add OWASP to technique detail Frameworks tab

**Files:**
- Modify: `src/pages/TechniqueDetail.tsx`

- [ ] **Step 1: Add OWASP section in FrameworksTab function (~line 440)**

After the cloud controls section, add:

```tsx
{/* OWASP Categories */}
{data.owasp && data.owasp.length > 0 && (
  <section>
    <h3 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
      OWASP Categories ({data.owasp.length})
    </h3>
    <div className="flex flex-wrap gap-1.5">
      {data.owasp.map((cat) => (
        <EntityLink
          key={`${cat.categoryId}-${cat.framework}`}
          type="owasp"
          attackId={cat.categoryId}
          name={cat.name}
        />
      ))}
    </div>
    <div className="pt-2">
      <Link to="/frameworks/owasp" className="text-xs text-[var(--accent-teal)] hover:underline">
        Browse all OWASP categories
      </Link>
    </div>
  </section>
)}
```

- [ ] **Step 2: Update isEmpty check (~line 420)**

Add `(data.owasp?.length ?? 0) === 0` to the isEmpty condition.

- [ ] **Step 3: Add EntityLink import if not present**

- [ ] **Step 4: Commit**

```bash
git add src/pages/TechniqueDetail.tsx
git commit -m "feat(ui): show OWASP categories on technique detail Frameworks tab"
```

---

### Task 13: Add OWASP to CVE detail page

**Files:**
- Modify: `api/v1/cves/[cveId].ts`
- Modify: `src/pages/CveDetail.tsx`

- [ ] **Step 1: Add OWASP query to CVE detail API**

In `api/v1/cves/[cveId].ts`, add to the `Promise.all`:

```ts
// OWASP categories via CWE overlap
// Note: cve_weaknesses PK is (cve_id, cwe_id) — cve_id lookup is indexed
query<{ categoryId: string; name: string; framework: string }>(
  `SELECT DISTINCT o.category_id AS "categoryId", o.name, o.framework
   FROM owasp_top10 o
   JOIN cve_weaknesses cw ON cw.cwe_id = ANY(o.cwe_ids)
   WHERE cw.cve_id = $1
   ORDER BY o.framework, o.category_id`,
  [id],
),
```

Add `owaspCategories` to the response JSON.

- [ ] **Step 2: Add OWASP section to CVE detail frontend**

In `src/pages/CveDetail.tsx`, add after CWE section:

```tsx
{data.owaspCategories?.length > 0 && (
  <div>
    <h4 className="text-xs font-bold text-[var(--text-secondary)] uppercase tracking-wider mb-2">
      OWASP Categories
    </h4>
    <div className="flex flex-wrap gap-1.5">
      {data.owaspCategories.map((cat) => (
        <EntityLink
          key={`${cat.categoryId}-${cat.framework}`}
          type="owasp"
          attackId={cat.categoryId}
          name={cat.name}
        />
      ))}
    </div>
  </div>
)}
```

- [ ] **Step 3: Update CveDetail type** in `src/lib/types.ts`

Add to the `CveDetail` interface (after line 536):

```ts
owaspCategories?: Array<{ categoryId: string; name: string; framework: string }>;
```

- [ ] **Step 4: Commit**

```bash
git add api/v1/cves/[cveId].ts src/pages/CveDetail.tsx src/lib/types.ts
git commit -m "feat(ui): show OWASP categories on CVE detail page"
```

---

### Task 14: Add OWASP to search page

**Important:** `ENTITY_PATH` and `ENTITY_COLOR` are both `Record<EntityType, string>` — adding `'owasp'` to `EntityType` (Task 8) without updating these maps causes compile errors. Must be done before or with Task 8's commit.

**Files:**
- Modify: `src/pages/Search.tsx`

- [ ] **Step 1: Add owasp to ENTITY_PATH + ENTITY_COLOR (lines 10-28)**

```ts
// In ENTITY_PATH:
owasp: 'frameworks/owasp',

// In ENTITY_COLOR:
owasp: 'text-[var(--accent-orange)]',
```

- [ ] **Step 2: Add owasp to totalCount (~line 85)**

```ts
(data?.owasp?.length ?? 0) +
```

- [ ] **Step 3: Add OWASP summary badge (~line 182)**

```tsx
{data.owasp && data.owasp.length > 0 && (
  <Badge label={`${data.owasp.length} OWASP`} variant="orange" />
)}
```

- [ ] **Step 4: Add OWASP results section (~line 288)**

```tsx
{data.owasp && data.owasp.length > 0 && (
  <section>
    <SectionHeader label="OWASP Categories" count={data.owasp.length} />
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg divide-y divide-[var(--border-color)]">
      {data.owasp.map((cat) => (
        <ResultRow
          key={cat.categoryId}
          attackId={cat.categoryId}
          name={`${cat.name} (${cat.framework})`}
          type="owasp"
          context={cat.isDraft ? 'DRAFT' : undefined}
        />
      ))}
    </div>
  </section>
)}
```

- [ ] **Step 5: Commit**

```bash
git add src/pages/Search.tsx
git commit -m "feat(ui): add OWASP categories to search results"
```

---

## Phase 5: Relationship Model + Chrome

### Task 15: Add edges to relationship model

**Files:**
- Modify: `src/components/relationships/RelationshipModel.tsx:66-100`

- [ ] **Step 1: Add edges to EDGES array**

At `RelationshipModel.tsx:99` (end of EDGES array), add:

```ts
{ from: 'owasp', to: 'technique', label: 'maps via CWE', style: 'dashed' },
{ from: 'owasp', to: 'atlas', label: 'AI risks', style: 'dashed' },
{ from: 'owasp', to: 'cve', label: 'categorizes', style: 'dashed' },
```

- [ ] **Step 2: Update OWASP node description (line 42)**

Change:
```ts
description: 'Web security risks mapped to techniques via CWE',
```
To:
```ts
description: 'Web, ML, and LLM security risks mapped to techniques via CWE + ATLAS',
```

- [ ] **Step 3: Commit**

```bash
git add src/components/relationships/RelationshipModel.tsx
git commit -m "feat(ui): add OWASP edges + update node description in relationship model"
```

---

### Task 16: Update sidebar tooltip

**Files:**
- Modify: `src/components/layout/Sidebar.tsx:70`

- [ ] **Step 1: Update OWASP tooltip**

Change:
```ts
{ path: '/frameworks/owasp', label: 'OWASP Top 10', tooltip: 'web application security risks mapped to ATT&CK techniques via CWE' },
```
To:
```ts
{ path: '/frameworks/owasp', label: 'OWASP Top 10', tooltip: 'web, ML, and LLM security risks mapped to ATT&CK + ATLAS via CWE' },
```

- [ ] **Step 2: Commit**

```bash
git add src/components/layout/Sidebar.tsx
git commit -m "feat(ui): update OWASP sidebar tooltip for ML/LLM"
```

---

### Task 17: Update about modal

**Files:**
- Modify: `src/App.tsx:229`

- [ ] **Step 1: Update OWASP bullet**

Change:
```tsx
<li><strong>Frameworks</strong> — OWASP Top 10, NIST 800-53, MITRE Engage, D3FEND, RE&CT, VERIS incident classification, Azure + GCP cloud controls</li>
```
To:
```tsx
<li><strong>Frameworks</strong> — OWASP Top 10 (Web 2021, ML 2023, LLM 2025), NIST 800-53, MITRE Engage, D3FEND, RE&CT, VERIS incident classification, Azure + GCP cloud controls</li>
```

- [ ] **Step 2: Commit**

```bash
git add src/App.tsx
git commit -m "feat(ui): update about modal with ML/LLM OWASP coverage"
```

---

## Phase 6: Verification

### Task 18: End-to-end verification

- [ ] **Step 1: Verify OWASP list page** — all 3 framework tabs work, ML shows DRAFT badges
- [ ] **Step 2: Verify OWASP detail** — expand ML01, see ATLAS technique "AML.T0043 Craft Adversarial Data"
- [ ] **Step 3: Verify technique detail** — navigate to any technique, check Frameworks tab for OWASP section
- [ ] **Step 4: Verify ATLAS technique** — navigate to AML.T0043, check Frameworks tab shows ML01
- [ ] **Step 5: Verify CVE detail** — find a CVE with CWE-79, check for OWASP badges (A03 Injection, LLM05)
- [ ] **Step 6: Verify search** — search "injection", confirm OWASP categories appear
- [ ] **Step 7: Verify relationship model** — open Data Model, confirm 3 new edges from OWASP
- [ ] **Step 8: Verify A2A** — test `get_owasp_top10` with `framework=ml-2023`
- [ ] **Step 9: Final commit + deploy**

```bash
git push origin main
```
