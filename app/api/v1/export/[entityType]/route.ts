import { NextRequest } from 'next/server';
import { query } from '../../lib/db.js';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';
import { exportSchema } from '../../lib/validate.js';
import { NextResponse } from 'next/server';

export { OPTIONS };

/** Convert an array of objects to CSV text */
function toCsv(rows: Record<string, unknown>[]): string {
  if (rows.length === 0) return '';
  const headers = Object.keys(rows[0]);
  const escape = (v: unknown): string => {
    if (v === null || v === undefined) return '';
    const s = Array.isArray(v) ? v.join(';') : String(v);
    return s.includes(',') || s.includes('"') || s.includes('\n')
      ? `"${s.replace(/"/g, '""')}"`
      : s;
  };
  const headerLine = headers.join(',');
  const dataLines = rows.map((row) => headers.map((h) => escape(row[h])).join(','));
  return [headerLine, ...dataLines].join('\n');
}

const ENTITY_QUERIES: Record<string, string> = {
  techniques: `
    SELECT attack_id, name, description, url, platforms, is_subtechnique, is_revoked, is_deprecated, domain, stix_modified
    FROM techniques ORDER BY attack_id ASC LIMIT 10000`,
  groups: `
    SELECT attack_id, name, description, url, aliases, is_revoked, is_deprecated, domain, stix_modified
    FROM threat_groups ORDER BY attack_id ASC LIMIT 10000`,
  software: `
    SELECT attack_id, name, description, url, type, platforms, aliases, is_revoked, is_deprecated, domain, stix_modified
    FROM attack_software ORDER BY attack_id ASC LIMIT 10000`,
  mitigations: `
    SELECT attack_id, name, description, url, is_revoked, is_deprecated, domain, stix_modified
    FROM mitigations ORDER BY attack_id ASC LIMIT 10000`,
  campaigns: `
    SELECT attack_id, name, description, url, aliases, first_seen, last_seen, is_revoked, is_deprecated, domain
    FROM campaigns ORDER BY attack_id ASC LIMIT 10000`,
  data_sources: `
    SELECT attack_id, name, description, url, is_revoked, is_deprecated, domain
    FROM data_sources ORDER BY attack_id ASC LIMIT 10000`,
  tactics: `
    SELECT attack_id, name, description, url, sort_order, domain
    FROM tactics ORDER BY sort_order ASC NULLS LAST LIMIT 10000`,
  sectors: `
    SELECT name, slug FROM sectors ORDER BY name ASC LIMIT 10000`,
  owasp: `
    SELECT category_id, name, description, url, framework, cwe_ids, atlas_technique_ids, is_draft
    FROM owasp_top10 ORDER BY framework, category_id ASC LIMIT 10000`,
};

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ entityType: string }> }
) {
  const { entityType: rawEntityType } = await params;
  const format = req.nextUrl.searchParams.get('format') ?? 'json';

  const parsed = exportSchema.safeParse({
    entityType: rawEntityType,
    format,
  });

  if (!parsed.success) {
    return withCors(errorResponse(400,
      'Invalid entityType or format. entityType must be one of: techniques, groups, software, mitigations, campaigns, data_sources, tactics, sectors, owasp. format must be csv or json.',
      'VALIDATION_ERROR',
    ));
  }

  const { entityType } = parsed.data;
  const sql = ENTITY_QUERIES[entityType];

  const result = await query(sql);
  const rows = result.rows as Record<string, unknown>[];

  if (parsed.data.format === 'csv') {
    const csv = toCsv(rows);
    const response = new NextResponse(csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="${entityType}.csv"`,
      },
    });
    return withCors(response);
  }

  return withCors(jsonResponse({ entityType, count: rows.length, data: rows }, 3600));
}
