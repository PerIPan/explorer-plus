import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from './lib/db.js';
import { withHandler } from './lib/middleware.js';
import { z } from 'zod';

const querySchema = z.object({
  domain: z.enum(['enterprise-attack', 'mobile-attack', 'ics-attack']).optional(),
});

/**
 * Lightweight endpoint returning all entity names + IDs for client-side fuzzy search.
 * Cached aggressively — data only changes on re-seed.
 */
async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = querySchema.safeParse(req.query);
  const domain = parsed.success ? parsed.data.domain ?? null : null;

  const domainWhere = domain ? ` AND domain = $1` : '';
  const domainParams = domain ? [domain] : [];

  const [techniques, groups, software, campaigns, mitigations, tactics, externalActors] = await Promise.all([
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM techniques
       WHERE is_revoked = false AND is_deprecated = false AND is_subtechnique = false${domainWhere}
       ORDER BY name`,
      domainParams,
    ),
    // Groups span domains — never filtered
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT attack_id AS "attackId", name, domain FROM threat_groups
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
    `),
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM attack_software
       WHERE is_revoked = false AND is_deprecated = false${domainWhere}
       ORDER BY name`,
      domainParams,
    ),
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM campaigns
       WHERE is_revoked = false AND is_deprecated = false${domainWhere}
       ORDER BY name`,
      domainParams,
    ),
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM mitigations
       WHERE is_revoked = false AND is_deprecated = false${domainWhere}
       ORDER BY name`,
      domainParams,
    ),
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM tactics${domain ? ` WHERE domain = $1` : ''}
       ORDER BY sort_order`,
      domainParams,
    ),
    // External actors are not domain-scoped
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT name AS "attackId", name, NULL as domain FROM external_actors ORDER BY name
    `),
  ]);

  const entities = [
    ...techniques.rows.map(r => ({ ...r, type: 'technique' })),
    ...groups.rows.map(r => ({ ...r, type: 'group' })),
    ...software.rows.map(r => ({ ...r, type: 'software' })),
    ...campaigns.rows.map(r => ({ ...r, type: 'campaign' })),
    ...mitigations.rows.map(r => ({ ...r, type: 'mitigation' })),
    ...tactics.rows.map(r => ({ ...r, type: 'tactic' })),
    ...externalActors.rows.map(r => ({ ...r, type: 'external_actor' })),
  ];

  res.status(200).json({ data: entities, total: entities.length });
}

export default withHandler(handler, { cacheTtl: 86400 }); // cache 24h
