import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../_lib/db';
import { withHandler } from '../_lib/middleware';
import { attackIdSchema } from '../_lib/validate';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const parsed = attackIdSchema.safeParse(req.query.attackId);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
  }
  const attackId = parsed.data;

  const softwareResult = await query<{
    id: string; attackId: string; stixId: string | null; name: string;
    description: string | null; url: string | null; type: string;
    platforms: string[] | null; aliases: string[] | null; isRevoked: boolean;
    isDeprecated: boolean; domain: string | null; stixCreated: string | null;
    stixModified: string | null;
  }>(
    `SELECT
       id, attack_id AS "attackId", stix_id AS "stixId", name, description, url,
       type, platforms, aliases, is_revoked AS "isRevoked",
       is_deprecated AS "isDeprecated", domain,
       stix_created AS "stixCreated", stix_modified AS "stixModified"
     FROM attack_software WHERE attack_id = $1`,
    [attackId],
  );

  if (softwareResult.rows.length === 0) {
    res.status(404).json({ error: 'Software not found', code: 'NOT_FOUND' });
    return;
  }

  const software = softwareResult.rows[0];
  const softwareId = software.id;

  const [techniquesResult, groupsResult] = await Promise.all([
    query<{ attackId: string; name: string; procedure: string | null; platforms: string[] | null }>(
      `SELECT t.attack_id AS "attackId", t.name, st.description AS procedure, t.platforms
       FROM software_techniques st
       JOIN techniques t ON t.id = st.technique_id
       WHERE st.software_id = $1
       ORDER BY t.name ASC`,
      [softwareId],
    ),
    query<{ attackId: string; name: string; description: string | null }>(
      `SELECT tg.attack_id AS "attackId", tg.name, gs.description
       FROM group_software gs
       JOIN threat_groups tg ON tg.id = gs.group_id
       WHERE gs.software_id = $1
       ORDER BY tg.name ASC`,
      [softwareId],
    ),
  ]);

  res.status(200).json({
    ...software,
    techniques: techniquesResult.rows,
    groups: groupsResult.rows,
  });
}

export default withHandler(handler, { cacheTtl: 3600 });
