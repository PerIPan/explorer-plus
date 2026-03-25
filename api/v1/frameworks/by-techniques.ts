import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';

/**
 * Aggregate VERIS + Cloud Control mappings for a set of technique IDs.
 * Used by actor/software/campaign profile views to show framework coverage.
 *
 * GET /frameworks/by-techniques?ids=T1566,T1059,T1078
 */
async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const raw = typeof req.query.ids === 'string' ? req.query.ids : '';
  const ids = raw.split(',').map((s) => s.trim()).filter((s) => /^T\d{4}(\.\d{3})?$/.test(s)).slice(0, 200);

  if (ids.length === 0) {
    res.status(200).json({ veris: [], cloud: [] });
    return;
  }

  const [verisResult, cloudResult] = await Promise.all([
    query<{ verisId: string; count: string }>(
      `SELECT veris_id AS "verisId", COUNT(*)::text AS count
       FROM veris_mappings
       WHERE attack_technique_id = ANY($1::text[])
       GROUP BY veris_id
       ORDER BY COUNT(*) DESC`,
      [ids],
    ),
    query<{ provider: string; controlId: string; controlName: string; mappingType: string | null; count: string }>(
      `SELECT
         provider,
         control_id AS "controlId",
         MAX(control_name) AS "controlName",
         mapping_type AS "mappingType",
         COUNT(DISTINCT attack_technique_id)::text AS count
       FROM cloud_control_mappings
       WHERE attack_technique_id = ANY($1::text[])
       GROUP BY provider, control_id, mapping_type
       ORDER BY provider, COUNT(*) DESC`,
      [ids],
    ),
  ]);

  res.status(200).json({
    veris: verisResult.rows.map((r) => ({ ...r, count: parseInt(r.count, 10) })),
    cloud: cloudResult.rows.map((r) => ({ ...r, count: parseInt(r.count, 10) })),
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
