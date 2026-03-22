import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db';
import { withHandler } from './lib/middleware';

/**
 * Lightweight endpoint returning all entity names + IDs for client-side fuzzy search.
 * Cached aggressively — data only changes on re-seed.
 */
async function handler(_req: VercelRequest, res: VercelResponse): Promise<void> {
  const [techniques, groups, software, campaigns, mitigations, tactics] = await Promise.all([
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM techniques
      WHERE is_revoked = false AND is_deprecated = false AND is_subtechnique = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM threat_groups
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM attack_software
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM campaigns
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM mitigations
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string }>(`
      SELECT attack_id AS "attackId", name FROM tactics
      ORDER BY sort_order
    `),
  ]);

  const entities = [
    ...techniques.rows.map(r => ({ ...r, type: 'technique' })),
    ...groups.rows.map(r => ({ ...r, type: 'group' })),
    ...software.rows.map(r => ({ ...r, type: 'software' })),
    ...campaigns.rows.map(r => ({ ...r, type: 'campaign' })),
    ...mitigations.rows.map(r => ({ ...r, type: 'mitigation' })),
    ...tactics.rows.map(r => ({ ...r, type: 'tactic' })),
  ];

  res.status(200).json({ data: entities, total: entities.length });
}

export default withHandler(handler, { cacheTtl: 86400 }); // cache 24h
