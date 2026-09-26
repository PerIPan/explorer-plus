import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { paginationSchema } from '../../lib/validate';
import { escapeLikePattern } from '../../lib/queries';
import { z } from 'zod';

export { OPTIONS };

const querySchema = paginationSchema.extend({
  type: z.string().optional(),
  source: z.string().optional(),
  malware: z.string().optional(),
  q: z.string().min(1).max(200).optional(),
  since: z.string().optional(),
  sector: z.string().max(50).optional(),
});

export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid query parameters', 'VALIDATION_ERROR'));
  }

  const { page, limit, type, source, malware, q, since, order, sector } = parsed.data;
  const offset = (page - 1) * limit;

  const params: unknown[] = [];
  const conditions: string[] = [];

  // Sector filter: show IOCs linked to sector groups OR IOCs with no technique links.
  //
  // PERF: the inner semi-join is nested rather than flattened on purpose. The
  // flat form (technique_iocs JOIN group_techniques JOIN group_sectors JOIN
  // sectors) materialises one row per (ioc, technique, group) triple before the
  // IN dedupes it — 681k technique_iocs fanned out over 5k group_techniques.
  // Measured on Neon: the COUNT(*) below ran >12 min without finishing.
  // Resolving `sector -> technique_id` FIRST (a few hundred ids from three tiny
  // tables) turns the outer half into indexed lookups on
  // idx_technique_iocs_technique_id. Same semantics: `IN` is a semi-join in
  // both forms, so the duplicate ioc_ids the flat version produced were never
  // observable.
  if (sector) {
    params.push(sector);
    conditions.push(`(
      i.id IN (
        SELECT ti2.ioc_id FROM technique_iocs ti2
        WHERE ti2.technique_id IN (
          SELECT gt.technique_id FROM group_techniques gt
          JOIN group_sectors gs ON gs.group_id = gt.group_id
          JOIN sectors s ON s.id = gs.sector_id
          WHERE s.slug = $${params.length}
        )
      )
      OR NOT EXISTS (SELECT 1 FROM technique_iocs ti3 WHERE ti3.ioc_id = i.id)
    )`);
  }

  if (type) {
    params.push(type);
    conditions.push(`i.type = $${params.length}`);
  } else if (source !== 'cisa_kev') {
    // Exclude CVEs by default — they have their own /cves endpoint
    // But allow them through when explicitly filtering by cisa_kev source
    conditions.push(`i.type != 'cve'`);
  }

  if (source) {
    params.push(source);
    conditions.push(`i.source = $${params.length}`);
  }

  if (malware) {
    params.push(`%${escapeLikePattern(malware)}%`);
    conditions.push(`i.malware_family ILIKE $${params.length}`);
  }

  if (q) {
    params.push(`%${escapeLikePattern(q)}%`);
    conditions.push(
      `(i.value ILIKE $${params.length} OR i.malware_family ILIKE $${params.length})`,
    );
  }

  if (since) {
    const d = new Date(since);
    if (!isNaN(d.getTime())) {
      params.push(d.toISOString());
      conditions.push(`i.first_seen >= $${params.length}`);
    }
  }

  const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  // Default to DESC (latest first) when no explicit order given
  const effectiveOrder = rawParams.order ? order : 'desc';
  const sortDir = effectiveOrder === 'asc' ? 'ASC' : 'DESC';

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) FROM ioc_entries i ${whereClause}`,
    params,
  );
  const total = parseInt(countResult.rows[0].count, 10);

  params.push(limit, offset);
  const dataResult = await query<{
    id: string;
    type: string;
    value: string;
    source: string | null;
    malware_family: string | null;
    first_seen: string | null;
    source_ref: string | null;
    description: string | null;
    created_at: string;
    technique_count: string;
  }>(
    // PERF: technique_count is a correlated COUNT, not a LEFT JOIN + aggregate.
    // The join form had to merge all 161k matching ioc_entries against all 681k
    // technique_iocs rows and aggregate the lot before the top-N sort could run
    // — 12.7s measured, of which 8.5s was the technique_iocs index scan alone.
    // As a subquery it is evaluated only for the rows actually returned.
    //
    // `GROUP BY i.id` is retained deliberately even though nothing aggregates
    // any more. It keeps the planner on the ordered ioc_entries_pkey path, and
    // therefore keeps the row order the top-N sort receives — `first_seen` has
    // ~30k tied values at second granularity and the tie order was an artefact
    // of that input order. Dropping the GROUP BY reshuffled 14 of the first 50
    // rows; keeping it reproduces the previous output byte for byte.
    `SELECT i.id, i.type, i.value, i.source, i.malware_family, i.first_seen, i.source_ref, i.description, i.created_at,
            (SELECT COUNT(*) FROM technique_iocs ti WHERE ti.ioc_id = i.id) AS technique_count
     FROM ioc_entries i
     ${whereClause}
     GROUP BY i.id
     ORDER BY i.first_seen ${sortDir} NULLS LAST
     LIMIT $${params.length - 1} OFFSET $${params.length}`,
    params,
  );

  // Normalize field name for frontend compatibility
  const data = dataResult.rows.map((r) => ({
    ...r,
    first_seen_at: r.first_seen,
    technique_count: parseInt(r.technique_count, 10),
  }));

  return withCors(jsonResponse({
    data,
    pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
  }, 1800));
}
