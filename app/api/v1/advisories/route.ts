import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
import { ADVISORY_ECOSYSTEM_CATEGORIES, ADVISORY_CATEGORY_KEYS } from '../../../../src/lib/advisoryEcosystems';
import { z } from 'zod';

export { OPTIONS };

/**
 * Unified advisories list: GHSA + OSV under one shape. GHSA holds the
 * reviewed OSS-package advisories we've been surfacing; OSV holds the OS,
 * distro, and kernel advisories. The two tables are disjoint by ingest —
 * our OSV cron skips GHSA-covered ecosystems AND drops records aliasing
 * any existing GHSA, so no row appears twice.
 *
 * Route shape mirrors the GHSA list endpoint so existing clients can
 * switch with minimal churn. Each row carries a `source: 'GHSA' | 'OSV'`
 * discriminator for the UI's chip rendering.
 *
 * ── PERFORMANCE SHAPE (read this before editing the SQL) ──────────────────
 *
 * This endpoint used to never return. Measured: curl gave up after 280 s and
 * the backend query was still `active` in pg_stat_activity 47 minutes later.
 * The reason was that the single `UNION ALL … ORDER BY … LIMIT 50` made the
 * planner evaluate every per-row subquery for all 1,945,966 OSV rows before it
 * could sort — including `package_count`, which is one lookup per row into
 * osv_affected (8.7M rows / 7.3 GB).
 *
 * It is now three stages, and the stage boundary is the point:
 *
 *   1. KEYS   — one cheap, index-ordered `LIMIT limit + offset` per branch.
 *               GHSA reads ghsa_advisories directly (34,836 rows). OSV reads
 *               the `osv_advisory_rank` matview, whose whole reason for
 *               existing is that the sort key is a COMPUTED value
 *               (`COALESCE(o.cvss_severity, cve.cvss_severity)`, NULL on
 *               892,866 of 1.9M rows) and therefore cannot be indexed on the
 *               base table. See scripts/migrate-advisory-rank.sql.
 *   2. PAGE   — merge the two key sets, apply the real LIMIT/OFFSET. Taking
 *               `limit + offset` from each branch is sufficient: the global
 *               top-(limit+offset) cannot contain a row that is not in its own
 *               branch's top-(limit+offset) under the same ordering.
 *   3. PAYLOAD— the ORIGINAL SELECT lists, verbatim, restricted to the ≤ limit
 *               keys on the page. The expensive per-row subqueries and the
 *               live cve_details LATERAL now run `limit` times, not 1.9M.
 *
 * The filters live in stage 1 only. Stage 3 needs no WHERE clause because the
 * keys already encode every predicate — which is also why the payload SQL
 * could be left character-for-character as it was.
 */

// Ecosystems we accept (union of GHSA list + OSV list that actually ships data).
// Case-preserved names — OSV uses 'Linux', 'Debian', 'Ubuntu', etc.; GHSA uses
// 'npm', 'pypi', 'go', lowercase. The UI sends the verbatim label from its
// dropdown; we coerce case at query time per source.
const ECOSYSTEM_RE = /^[A-Za-z][A-Za-z0-9._\s-]{0,49}$/;

const querySchema = paginationSchema.extend({
  q: z.string().min(3).max(200).optional(),
  source: z.enum(['GHSA', 'OSV']).optional(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']).optional(),
  ecosystem: z.string().regex(ECOSYSTEM_RE).optional(),
  /** High-level category shortcut. Expands to a list of ecosystems server-side
   *  — saves clients from maintaining per-category mapping tables. */
  category: z.enum(ADVISORY_CATEGORY_KEYS as [string, ...string[]]).optional(),
  since: z.string().optional(),
  has_cve: z.enum(['true', 'false']).optional(),
});

/**
 * Severity → sort bucket. The single source of truth for BOTH the SQL CASE in
 * ORDER_CLAUSE below and the `sev_rank` column baked into osv_advisory_rank.
 *
 * It is also what lets `?severity=` become an equality on that column: the map
 * is injective over the four values the zod enum admits, and every other
 * severity string (cve_details' 'NONE', and NULL) falls to 0. So
 * `COALESCE(o.cvss_severity, cve.cvss_severity) = 'HIGH'` and `sev_rank = 3`
 * select exactly the same rows.
 */
const SEVERITY_RANK: Record<string, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
};

/** The CASE expression, over an arbitrary severity column reference. */
const sevRankSql = (col: string): string => `
    CASE ${col}
      WHEN 'CRITICAL' THEN 4
      WHEN 'HIGH'     THEN 3
      WHEN 'MEDIUM'   THEN 2
      WHEN 'LOW'      THEN 1
      ELSE 0
    END`;

interface UnifiedRow {
  advisory_id: string;
  source: 'GHSA' | 'OSV';
  cve_id: string | null;
  summary: string | null;
  severity: string | null;
  cvss_score: string | null;
  published_at: string | null;
  ecosystems: string[] | null;
  package_count: string;
}

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => {
    rawParams[k] = v;
  });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, q, source, severity, ecosystem, category, since, has_cve } = parsed.data;
  const offset = (page - 1) * limit;

  // Category → ecosystem list. If `ecosystem` is also set, we honour both and
  // rely on the SQL branches to intersect (the specific ecosystem must be
  // inside the category bucket to match). Mostly users pick one OR the other.
  const categoryEcos = category
    ? ADVISORY_ECOSYSTEM_CATEGORIES[category as keyof typeof ADVISORY_ECOSYSTEM_CATEGORIES].ecosystems
    : null;

  // Fixed ordering: severity first (CRITICAL → HIGH → MEDIUM → LOW → unknown),
  // newest-in-severity-bucket ties broken by published_at DESC, then stable
  // by advisory_id. Matches user intent "severity first, newest within that".
  // We don't expose an `order` toggle — the list is an ops view, not a date
  // history; critical new items should always surface at the top.
  //
  // Applied to the ≤ limit payload rows, over the LIVE severity, exactly as
  // before. The key stages below order by the materialised `sev_rank`, which is
  // the same expression as of the last matview refresh.
  const ORDER_CLAUSE = `${sevRankSql('severity')} DESC,
    published_at DESC NULLS LAST,
    advisory_id DESC
  `.trim();

  /** Ordering over the key CTEs, which carry sev_rank pre-computed. */
  const KEY_ORDER_CLAUSE = `
    sev_rank DESC,
    published_at DESC NULLS LAST,
    advisory_id DESC
  `.trim();

  const sinceIso = (() => {
    if (!since) return null;
    const d = new Date(since);
    return isNaN(d.getTime()) ? null : d.toISOString();
  })();

  // Category is a convenience filter that also narrows source: `oss-packages`
  // implies GHSA only; the three OSV categories imply OSV only. Explicit
  // `source` param is overridden by `category` when they disagree.
  const effectiveSource = category
    ? (category === 'oss-packages' ? 'GHSA' : 'OSV')
    : source;
  const wantGhsa = !effectiveSource || effectiveSource === 'GHSA';
  const wantOsvRequested = !effectiveSource || effectiveSource === 'OSV';

  // --- Build GHSA branch filters -------------------------------------------
  const ghsaParams: unknown[] = [];
  const ghsaConds: string[] = ['g.withdrawn_at IS NULL'];
  if (wantGhsa) {
    if (severity) {
      ghsaParams.push(severity);
      ghsaConds.push(`g.severity = $${ghsaParams.length}`);
    }
    if (q) {
      ghsaParams.push(`%${escapeLikePattern(q)}%`);
      ghsaConds.push(
        `(g.ghsa_id ILIKE $${ghsaParams.length} OR g.cve_id ILIKE $${ghsaParams.length} OR g.summary ILIKE $${ghsaParams.length})`,
      );
    }
    if (sinceIso) {
      ghsaParams.push(sinceIso);
      ghsaConds.push(`g.published_at >= $${ghsaParams.length}`);
    }
    if (has_cve === 'true') ghsaConds.push('g.cve_id IS NOT NULL');
    if (has_cve === 'false') ghsaConds.push('g.cve_id IS NULL');
    if (ecosystem) {
      // GHSA uses lowercase ecosystem names internally; coerce the filter.
      ghsaParams.push(ecosystem.toLowerCase());
      ghsaConds.push(`g.ghsa_id IN (
        SELECT gp.ghsa_id FROM ghsa_packages gp
        JOIN packages p ON p.id = gp.package_id
        WHERE LOWER(p.ecosystem) = $${ghsaParams.length}
      )`);
    }
    if (categoryEcos && category === 'oss-packages') {
      // Category list is lowercase (npm/pypi/go/…) — matches packages.ecosystem.
      ghsaParams.push(categoryEcos);
      ghsaConds.push(`g.ghsa_id IN (
        SELECT gp.ghsa_id FROM ghsa_packages gp
        JOIN packages p ON p.id = gp.package_id
        WHERE LOWER(p.ecosystem) = ANY($${ghsaParams.length}::text[])
      )`);
    }
  }

  // --- Build OSV branch filters --------------------------------------------
  // These run against `osv_advisory_rank r`, which materialises the derived
  // severity bucket and the CVE-alias flag. Only `?q=` needs the base table
  // (summary + aliases text), so only `?q=` pulls osv_advisories into the key
  // CTE — `osvNeedsBase` tracks that.
  const osvParams: unknown[] = [];
  const osvConds: string[] = [];
  let osvNeedsBase = false;
  if (wantOsvRequested) {
    if (severity) {
      // Equality on the LEADING column of osv_advisory_rank_order_idx. See
      // SEVERITY_RANK above for why this is equivalent to the old
      // `COALESCE(o.cvss_severity, cve.cvss_severity) = $n`.
      osvParams.push(SEVERITY_RANK[severity]);
      osvConds.push(`r.sev_rank = $${osvParams.length}`);
    }
    if (q) {
      osvParams.push(`%${escapeLikePattern(q)}%`);
      const ph = `$${osvParams.length}`;
      osvConds.push(
        `(o.osv_id ILIKE ${ph} OR o.summary ILIKE ${ph} OR EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a ILIKE ${ph}))`,
      );
      osvNeedsBase = true;
    }
    if (sinceIso) {
      osvParams.push(sinceIso);
      osvConds.push(`r.published >= $${osvParams.length}::timestamptz`);
    }
    // `r.has_cve` is the materialised
    // `EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%')`.
    if (has_cve === 'true') osvConds.push(`r.has_cve`);
    if (has_cve === 'false') osvConds.push(`NOT r.has_cve`);
    if (ecosystem) {
      osvParams.push(ecosystem);
      osvConds.push(`r.ecosystem = $${osvParams.length}`);
    }
    if (categoryEcos && category !== 'oss-packages') {
      // OSV categories carry case-preserved names (Ubuntu, Debian, Linux, …).
      osvParams.push(categoryEcos);
      osvConds.push(`r.ecosystem = ANY($${osvParams.length}::text[])`);
    }
  }

  const ghsaWhere = ghsaConds.length ? `WHERE ${ghsaConds.join(' AND ')}` : '';
  const osvWhereRaw = osvConds.length ? `WHERE ${osvConds.join(' AND ')}` : '';

  // NOTE: the params array is (ghsaParams, osvParams, …). Each branch's
  // placeholders are renumbered at composition time because the two arrays
  // append into a single combined param list.
  const renumber = (clause: string, offsetBy: number): string =>
    clause.replace(/\$(\d+)/g, (_m, n) => `$${Number(n) + offsetBy}`);

  const osvWhere = renumber(osvWhereRaw, ghsaParams.length);

  // The OSV payload SELECT, unchanged from the pre-optimisation route. The
  // LATERAL join to cve_details via the first CVE alias backfills
  // cvss_severity/cvss_score for OSV rows where the distro didn't publish CVSS
  // data (Chainguard/Wolfi/MinimOS/Linux kernel etc. — ~46% of OSV).
  // cve_details.cve_id is the primary key so this is an indexed point lookup
  // per row. The backfill is derived at read time, nothing is persisted to
  // osv_advisories — monthly full ingest cannot overwrite it. It now runs for
  // the rows on the requested page only.
  const osvLateralJoin = `
      LEFT JOIN LATERAL (
        SELECT cd.cvss_severity, cd.cvss_score
        FROM cve_details cd
        WHERE cd.cve_id = ANY(o.aliases)
        LIMIT 1
      ) cve ON true
    `;

  /**
   * Compose the count + data SQL. `includeOsv` is false for the pre-migration
   * fallback (see the catch below), where either osv_advisories or the
   * osv_advisory_rank matview is missing.
   */
  const compose = (includeOsv: boolean) => {
    const wantOsv = wantOsvRequested && includeOsv;

    const countBranches: string[] = [];
    if (wantGhsa) {
      countBranches.push(`SELECT COUNT(*) AS n FROM ghsa_advisories g ${ghsaWhere}`);
    }
    if (wantOsv) {
      // Counted off the matview, not osv_advisories + LATERAL. The old count
      // took 18,000 ms measured, entirely because of that LATERAL.
      countBranches.push(`
        SELECT COUNT(*) AS n
        FROM osv_advisory_rank r
        ${osvNeedsBase ? 'JOIN osv_advisories o ON o.osv_id = r.osv_id AND o.ecosystem = r.ecosystem' : ''}
        ${osvWhere}
      `);
    }

    // --- Stage 1: keys ----------------------------------------------------
    // `$capIdx` is limit + offset. Each branch takes its own top-(limit+offset)
    // by the same ordering; stage 2 merges and applies the real window.
    const capIdx = ghsaParams.length + osvParams.length + 1;
    const keyBranches: string[] = [];
    if (wantGhsa) {
      keyBranches.push(`
        ghsa_keys AS (
          SELECT
            g.ghsa_id                              AS advisory_id,
            ''::text                               AS eco,
            'GHSA'::text                           AS source,
            (${sevRankSql('g.severity')})::int     AS sev_rank,
            g.published_at                         AS published_at
          FROM ghsa_advisories g
          ${ghsaWhere}
          ORDER BY ${KEY_ORDER_CLAUSE}
          LIMIT $${capIdx}
        )
      `);
    }
    if (wantOsv) {
      keyBranches.push(`
        osv_keys AS (
          SELECT
            r.osv_id      AS advisory_id,
            r.ecosystem   AS eco,
            'OSV'::text   AS source,
            r.sev_rank    AS sev_rank,
            r.published   AS published_at
          FROM osv_advisory_rank r
          ${osvNeedsBase ? 'JOIN osv_advisories o ON o.osv_id = r.osv_id AND o.ecosystem = r.ecosystem' : ''}
          ${osvWhere}
          ORDER BY ${KEY_ORDER_CLAUSE}
          LIMIT $${capIdx}
        )
      `);
    }

    // --- Stage 2: page ----------------------------------------------------
    const keyUnion = [wantGhsa ? 'SELECT * FROM ghsa_keys' : null, wantOsv ? 'SELECT * FROM osv_keys' : null]
      .filter(Boolean)
      .join(' UNION ALL ');
    const limitIdx = capIdx + 1;
    const offsetIdx = capIdx + 2;
    const pageCte = `
      page AS (
        SELECT * FROM (${keyUnion}) k
        ORDER BY ${KEY_ORDER_CLAUSE}
        LIMIT $${limitIdx} OFFSET $${offsetIdx}
      )
    `;

    // --- Stage 3: payload -------------------------------------------------
    // SELECT lists untouched. No WHERE beyond the key restriction — every
    // predicate is already encoded in `page`.
    const payloadBranches: string[] = [];
    if (wantGhsa) {
      payloadBranches.push(`
        SELECT
          g.ghsa_id        AS advisory_id,
          'GHSA'::text     AS source,
          g.cve_id         AS cve_id,
          g.summary        AS summary,
          g.severity       AS severity,
          g.cvss_score     AS cvss_score,
          g.published_at   AS published_at,
          (SELECT ARRAY_AGG(DISTINCT p.ecosystem)
             FROM ghsa_packages gp JOIN packages p ON p.id = gp.package_id
             WHERE gp.ghsa_id = g.ghsa_id)                         AS ecosystems,
          (SELECT COUNT(DISTINCT gp.package_id)
             FROM ghsa_packages gp WHERE gp.ghsa_id = g.ghsa_id)::text AS package_count
        FROM ghsa_advisories g
        WHERE g.ghsa_id IN (SELECT advisory_id FROM page WHERE source = 'GHSA')
      `);
    }
    if (wantOsv) {
      payloadBranches.push(`
        SELECT
          o.osv_id         AS advisory_id,
          'OSV'::text      AS source,
          (SELECT a FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%' LIMIT 1) AS cve_id,
          o.summary        AS summary,
          COALESCE(o.cvss_severity, cve.cvss_severity) AS severity,
          COALESCE(o.cvss_score, cve.cvss_score)       AS cvss_score,
          o.published      AS published_at,
          ARRAY[o.ecosystem]                                        AS ecosystems,
          (SELECT COUNT(*)
             FROM osv_affected oa
             WHERE oa.osv_id = o.osv_id AND oa.ecosystem = o.ecosystem)::text AS package_count
        FROM osv_advisories o
        ${osvLateralJoin}
        WHERE (o.osv_id, o.ecosystem) IN (SELECT advisory_id, eco FROM page WHERE source = 'OSV')
      `);
    }

    const countSql = `SELECT COALESCE(SUM(n), 0)::text AS total FROM (${countBranches.join(' UNION ALL ')}) c`;
    const dataSql = `
      WITH ${[...keyBranches, pageCte].join(',')}
      SELECT *
      FROM (${payloadBranches.join(' UNION ALL ')}) adv
      ORDER BY ${ORDER_CLAUSE}
    `;

    const countParams = wantOsv ? [...ghsaParams, ...osvParams] : ghsaParams;
    const dataParams = wantOsv
      ? [...ghsaParams, ...osvParams, limit + offset, limit, offset]
      : [...ghsaParams, limit + offset, limit, offset];

    return { countSql, dataSql, countParams, dataParams, empty: payloadBranches.length === 0 };
  };

  const emptyPage = () =>
    withCors(jsonResponse({ data: [], pagination: { page, limit, total: 0, totalPages: 0 } }, 60));

  let plan = compose(true);
  if (plan.empty) {
    // Defensive: shouldn't happen because source is optional.
    return emptyPage();
  }

  // Graceful fallback for pre-migration envs: if `osv_advisories` or the
  // `osv_advisory_rank` matview doesn't exist yet, drop the OSV branch and
  // retry with GHSA-only. Mirrors the `.catch(() => ({ rows: [] }))` pattern
  // used across other endpoints.
  let total = 0;
  let rows: { rows: UnifiedRow[] } = { rows: [] };
  try {
    const countRes = await query<{ total: string }>(plan.countSql, plan.countParams);
    total = parseInt(countRes.rows[0].total, 10);
    rows = await query<UnifiedRow>(plan.dataSql, plan.dataParams);
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    const missingOsv =
      msg.includes('does not exist') &&
      (msg.includes('osv_advisories') || msg.includes('osv_advisory_rank'));
    if (!missingOsv) throw err;
    if (!wantGhsa) return emptyPage();

    plan = compose(false);
    if (plan.empty) return emptyPage();
    const countRes = await query<{ total: string }>(plan.countSql, plan.countParams);
    total = parseInt(countRes.rows[0].total, 10);
    rows = await query<UnifiedRow>(plan.dataSql, plan.dataParams);
  }

  const data = rows.rows.map((r) => ({
    advisoryId: r.advisory_id,
    source: r.source,
    cveId: r.cve_id,
    summary: r.summary,
    severity: r.severity,
    cvssScore: r.cvss_score ? parseFloat(r.cvss_score) : null,
    publishedAt: r.published_at,
    ecosystems: r.ecosystems ?? [],
    packageCount: parseInt(r.package_count, 10),
  }));

  return withCors(
    jsonResponse(
      { data, pagination: { page, limit, total, totalPages: Math.ceil(total / limit) } },
      1800,
    ),
  );
}
