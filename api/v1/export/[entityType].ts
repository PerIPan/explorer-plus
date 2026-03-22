import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { exportSchema } from '../lib/validate.js';

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
    FROM techniques ORDER BY attack_id ASC`,
  groups: `
    SELECT attack_id, name, description, url, aliases, is_revoked, is_deprecated, domain, stix_modified
    FROM threat_groups ORDER BY attack_id ASC`,
  software: `
    SELECT attack_id, name, description, url, type, platforms, aliases, is_revoked, is_deprecated, domain, stix_modified
    FROM attack_software ORDER BY attack_id ASC`,
  mitigations: `
    SELECT attack_id, name, description, url, is_revoked, is_deprecated, domain, stix_modified
    FROM mitigations ORDER BY attack_id ASC`,
  campaigns: `
    SELECT attack_id, name, description, url, aliases, first_seen, last_seen, is_revoked, is_deprecated, domain
    FROM campaigns ORDER BY attack_id ASC`,
  data_sources: `
    SELECT attack_id, name, description, url, is_revoked, is_deprecated, domain
    FROM data_sources ORDER BY attack_id ASC`,
  tactics: `
    SELECT attack_id, name, description, url, sort_order, domain
    FROM tactics ORDER BY sort_order ASC NULLS LAST`,
  sectors: `
    SELECT name, slug FROM sectors ORDER BY name ASC`,
};

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = exportSchema.safeParse({
    entityType: req.query.entityType,
    format: req.query.format,
  });

  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid entityType or format. entityType must be one of: techniques, groups, software, mitigations, campaigns, data_sources, tactics, sectors. format must be csv or json.',
      code: 'VALIDATION_ERROR',
      details: parsed.error.flatten(),
    });
    return;
  }

  const { entityType, format } = parsed.data;
  const sql = ENTITY_QUERIES[entityType];

  const result = await query(sql);
  const rows = result.rows as Record<string, unknown>[];

  if (format === 'csv') {
    const csv = toCsv(rows);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${entityType}.csv"`);
    res.status(200).send(csv);
    return;
  }

  res.status(200).json({ entityType, count: rows.length, data: rows });
}

export default withHandler(handler, { cacheTtl: 3600 });
