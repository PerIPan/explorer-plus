import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse, errorResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { paginationSchema } from '../lib/validate';
import { escapeLikePattern } from '../lib/queries';
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
  since: z.string().optional(),
  has_cve: z.enum(['true', 'false']).optional(),
});

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

  const { page, limit, q, source, severity, ecosystem, since, has_cve, order } = parsed.data;
  const offset = (page - 1) * limit;
  const sortDir = order === 'asc' ? 'ASC' : 'DESC';

  const sinceIso = (() => {
    if (!since) return null;
    const d = new Date(since);
    return isNaN(d.getTime()) ? null : d.toISOString();
  })();

  // --- Build GHSA branch ----------------------------------------------------
  // The overall query is UNION ALL of a GHSA SELECT and an OSV SELECT. Each
  // branch filters itself; branches can be fully skipped if `source` narrows.

  const wantGhsa = !source || source === 'GHSA';
  const wantOsv = !source || source === 'OSV';

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
  }

  // --- Build OSV branch -----------------------------------------------------
  const osvParams: unknown[] = [];
  const osvConds: string[] = [];
  if (wantOsv) {
    if (severity) {
      osvParams.push(severity);
      osvConds.push(`o.cvss_severity = $${osvParams.length}`);
    }
    if (q) {
      osvParams.push(`%${escapeLikePattern(q)}%`);
      const ph = `$${osvParams.length}`;
      osvConds.push(
        `(o.osv_id ILIKE ${ph} OR o.summary ILIKE ${ph} OR EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a ILIKE ${ph}))`,
      );
    }
    if (sinceIso) {
      osvParams.push(sinceIso);
      osvConds.push(`o.published >= $${osvParams.length}::timestamptz`);
    }
    if (has_cve === 'true') {
      osvConds.push(`EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%')`);
    }
    if (has_cve === 'false') {
      osvConds.push(`NOT EXISTS (SELECT 1 FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%')`);
    }
    if (ecosystem) {
      osvParams.push(ecosystem);
      osvConds.push(`o.ecosystem = $${osvParams.length}`);
    }
  }

  const ghsaWhere = ghsaConds.length ? `WHERE ${ghsaConds.join(' AND ')}` : '';
  const osvWhere = osvConds.length ? `WHERE ${osvConds.join(' AND ')}` : '';

  // --- Compose & paginate ---------------------------------------------------
  // We SELECT both branches with identical column lists, UNION ALL, then
  // paginate. Count is computed with a separate UNION ALL of COUNT() queries
  // so the planner can use per-table indexes.
  //
  // NOTE: the params array below is (ghsaParams, osvParams, limit, offset).
  // Each branch's placeholders are renumbered at composition time because
  // the two arrays append into a single combined param list.

  const renumber = (clause: string, offsetBy: number): string =>
    clause.replace(/\$(\d+)/g, (_m, n) => `$${Number(n) + offsetBy}`);

  const osvWhereRenum = renumber(osvWhere, ghsaParams.length);

  const branches: string[] = [];
  const countBranches: string[] = [];
  if (wantGhsa) {
    branches.push(`
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
      ${ghsaWhere}
    `);
    countBranches.push(`SELECT COUNT(*) AS n FROM ghsa_advisories g ${ghsaWhere}`);
  }
  if (wantOsv) {
    branches.push(`
      SELECT
        o.osv_id         AS advisory_id,
        'OSV'::text      AS source,
        (SELECT a FROM unnest(o.aliases) a WHERE a LIKE 'CVE-%' LIMIT 1) AS cve_id,
        o.summary        AS summary,
        o.cvss_severity  AS severity,
        o.cvss_score     AS cvss_score,
        o.published      AS published_at,
        ARRAY[o.ecosystem]                                        AS ecosystems,
        (SELECT COUNT(*)
           FROM osv_affected oa
           WHERE oa.osv_id = o.osv_id AND oa.ecosystem = o.ecosystem)::text AS package_count
      FROM osv_advisories o
      ${osvWhereRenum}
    `);
    countBranches.push(`SELECT COUNT(*) AS n FROM osv_advisories o ${osvWhereRenum}`);
  }

  if (branches.length === 0) {
    // Defensive: shouldn't happen because source is optional.
    return withCors(jsonResponse({ data: [], pagination: { page, limit, total: 0, totalPages: 0 } }, 60));
  }

  const allParams = [...ghsaParams, ...osvParams];

  const countSql = `SELECT COALESCE(SUM(n), 0)::text AS total FROM (${countBranches.join(' UNION ALL ')}) c`;

  // Graceful fallback for pre-migration envs: if `osv_advisories` doesn't
  // exist yet, drop the OSV branch and retry with GHSA-only. Mirrors the
  // `.catch(() => ({ rows: [] }))` pattern used across other endpoints.
  let total = 0;
  let rows: { rows: UnifiedRow[] } = { rows: [] };
  try {
    const countRes = await query<{ total: string }>(countSql, allParams);
    total = parseInt(countRes.rows[0].total, 10);

    // For the data query we append limit + offset as trailing params.
    allParams.push(limit, offset);
    const limitIdx = allParams.length - 1;
    const offsetIdx = allParams.length;

    const dataSql = `
      SELECT *
      FROM (${branches.join(' UNION ALL ')}) adv
      ORDER BY published_at ${sortDir} NULLS LAST, advisory_id DESC
      LIMIT $${limitIdx} OFFSET $${offsetIdx}
    `;
    rows = await query<UnifiedRow>(dataSql, allParams);
  } catch (err) {
    const msg = err instanceof Error ? err.message : '';
    if (!msg.includes('osv_advisories') || !msg.includes('does not exist')) {
      throw err;
    }
    // osv_advisories missing — retry with GHSA-only.
    if (!wantGhsa) {
      return withCors(jsonResponse({
        data: [],
        pagination: { page, limit, total: 0, totalPages: 0 },
      }, 60));
    }
    const ghsaOnlyCount = `SELECT COUNT(*)::text AS total FROM ghsa_advisories g ${ghsaWhere}`;
    const countRes = await query<{ total: string }>(ghsaOnlyCount, ghsaParams);
    total = parseInt(countRes.rows[0].total, 10);

    const ghsaOnlyData = `
      SELECT *
      FROM (${branches[0]}) adv
      ORDER BY published_at ${sortDir} NULLS LAST, advisory_id DESC
      LIMIT $${ghsaParams.length + 1} OFFSET $${ghsaParams.length + 2}
    `;
    rows = await query<UnifiedRow>(ghsaOnlyData, [...ghsaParams, limit, offset]);
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
      300,
    ),
  );
}
