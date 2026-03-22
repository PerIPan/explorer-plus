import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';
import { attackIdSchema } from '../lib/validate.js';
import { z } from 'zod';
import type { GraphNode, GraphEdge } from '../lib/types.js';

const querySchema = z.object({
  limit: z.coerce.number().int().positive().max(500).default(200),
});

type EntityType = 'technique' | 'group' | 'software' | 'mitigation' | 'campaign' | 'data_source' | 'tactic';

interface EntityRow {
  id: string;
  attackId: string;
  name: string;
  type: EntityType;
}

/** Find entity in any table by attack_id */
async function findEntity(attackId: string): Promise<EntityRow | null> {
  const tables: Array<{ table: string; type: EntityType }> = [
    { table: 'techniques',    type: 'technique'   },
    { table: 'threat_groups', type: 'group'        },
    { table: 'attack_software', type: 'software'  },
    { table: 'mitigations',   type: 'mitigation'  },
    { table: 'campaigns',     type: 'campaign'    },
    { table: 'data_sources',  type: 'data_source' },
    { table: 'tactics',       type: 'tactic'      },
  ];

  for (const { table, type } of tables) {
    const result = await query<{ id: string; attackId: string; name: string }>(
      `SELECT id, attack_id AS "attackId", name FROM ${table} WHERE attack_id = $1 LIMIT 1`,
      [attackId],
    );
    if (result.rows.length > 0) {
      return { ...result.rows[0], type };
    }
  }
  return null;
}

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const idParsed = attackIdSchema.safeParse(req.query.attackId);
  if (!idParsed.success) {
    res.status(400).json({ error: 'Invalid attack_id format', code: 'VALIDATION_ERROR' });
    return;
  }

  const limitParsed = querySchema.safeParse(req.query);
  const nodeLimit = limitParsed.success ? limitParsed.data.limit : 200;

  const attackId = idParsed.data;
  const entity = await findEntity(attackId);

  if (!entity) {
    res.status(404).json({ error: 'Entity not found', code: 'NOT_FOUND' });
    return;
  }

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seen = new Set<string>();

  const center: GraphNode = { id: entity.id, label: entity.name, type: entity.type, attackId: entity.attackId };
  seen.add(entity.id);

  /**
   * Add a node (dedup), return true if added and under limit.
   */
  function addNode(node: GraphNode): boolean {
    if (seen.has(node.id) || nodes.length >= nodeLimit) return false;
    seen.add(node.id);
    nodes.push(node);
    return true;
  }

  // Build relationship queries based on entity type
  if (entity.type === 'technique') {
    const [groupsRes, softRes, mitRes, campRes, tacticRes, subRes] = await Promise.all([
      query<{ id: string; attackId: string; name: string }>(
        `SELECT tg.id, tg.attack_id AS "attackId", tg.name
         FROM group_techniques gt JOIN threat_groups tg ON tg.id = gt.group_id
         WHERE gt.technique_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string; type: string }>(
        `SELECT sw.id, sw.attack_id AS "attackId", sw.name, sw.type
         FROM software_techniques st JOIN attack_software sw ON sw.id = st.software_id
         WHERE st.technique_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT m.id, m.attack_id AS "attackId", m.name
         FROM mitigation_techniques mt JOIN mitigations m ON m.id = mt.mitigation_id
         WHERE mt.technique_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT c.id, c.attack_id AS "attackId", c.name
         FROM campaign_techniques ct JOIN campaigns c ON c.id = ct.campaign_id
         WHERE ct.technique_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT ta.id, ta.attack_id AS "attackId", ta.name
         FROM technique_tactics tt JOIN tactics ta ON ta.id = tt.tactic_id
         WHERE tt.technique_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT id, attack_id AS "attackId", name FROM techniques
         WHERE parent_technique_id = $1 AND is_revoked = false AND is_deprecated = false`,
        [entity.id],
      ),
    ]);

    for (const r of groupsRes.rows)   { if (addNode({ id: r.id, label: r.name, type: 'group',     attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of softRes.rows)     { if (addNode({ id: r.id, label: r.name, type: 'software',  attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of mitRes.rows)      { if (addNode({ id: r.id, label: r.name, type: 'mitigation',attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'mitigates' }); }
    for (const r of campRes.rows)     { if (addNode({ id: r.id, label: r.name, type: 'campaign',  attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'uses' }); }
    for (const r of tacticRes.rows)   { if (addNode({ id: r.id, label: r.name, type: 'tactic',    attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'belongs_to' }); }
    for (const r of subRes.rows)      { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'subtechnique' }); }
  }

  else if (entity.type === 'group') {
    const [techRes, softRes, campRes, sectorRes] = await Promise.all([
      query<{ id: string; attackId: string; name: string }>(
        `SELECT t.id, t.attack_id AS "attackId", t.name
         FROM group_techniques gt JOIN techniques t ON t.id = gt.technique_id
         WHERE gt.group_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT sw.id, sw.attack_id AS "attackId", sw.name
         FROM group_software gs JOIN attack_software sw ON sw.id = gs.software_id
         WHERE gs.group_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT c.id, c.attack_id AS "attackId", c.name
         FROM group_campaigns gc JOIN campaigns c ON c.id = gc.campaign_id
         WHERE gc.group_id = $1`,
        [entity.id],
      ),
      query<{ id: string; name: string; slug: string | null }>(
        `SELECT s.id, s.name, s.slug
         FROM group_sectors gs JOIN sectors s ON s.id = gs.sector_id
         WHERE gs.group_id = $1`,
        [entity.id],
      ),
    ]);

    for (const r of techRes.rows)    { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of softRes.rows)    { if (addNode({ id: r.id, label: r.name, type: 'software',  attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of campRes.rows)    { if (addNode({ id: r.id, label: r.name, type: 'campaign',  attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'attributed_to' }); }
    for (const r of sectorRes.rows)  { if (addNode({ id: r.id, label: r.name, type: 'sector',    attackId: r.slug ?? r.id })) edges.push({ source: entity.id, target: r.id, relationship: 'targets' }); }
  }

  else if (entity.type === 'software') {
    const [techRes, groupRes, campRes] = await Promise.all([
      query<{ id: string; attackId: string; name: string }>(
        `SELECT t.id, t.attack_id AS "attackId", t.name
         FROM software_techniques st JOIN techniques t ON t.id = st.technique_id
         WHERE st.software_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT tg.id, tg.attack_id AS "attackId", tg.name
         FROM group_software gs JOIN threat_groups tg ON tg.id = gs.group_id
         WHERE gs.software_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT c.id, c.attack_id AS "attackId", c.name
         FROM campaign_software cs JOIN campaigns c ON c.id = cs.campaign_id
         WHERE cs.software_id = $1`,
        [entity.id],
      ),
    ]);

    for (const r of techRes.rows)  { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of groupRes.rows) { if (addNode({ id: r.id, label: r.name, type: 'group',     attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'uses' }); }
    for (const r of campRes.rows)  { if (addNode({ id: r.id, label: r.name, type: 'campaign',  attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'uses' }); }
  }

  else if (entity.type === 'mitigation') {
    const techRes = await query<{ id: string; attackId: string; name: string }>(
      `SELECT t.id, t.attack_id AS "attackId", t.name
       FROM mitigation_techniques mt JOIN techniques t ON t.id = mt.technique_id
       WHERE mt.mitigation_id = $1`,
      [entity.id],
    );
    for (const r of techRes.rows) { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'mitigates' }); }
  }

  else if (entity.type === 'campaign') {
    const [techRes, softRes, groupRes] = await Promise.all([
      query<{ id: string; attackId: string; name: string }>(
        `SELECT t.id, t.attack_id AS "attackId", t.name
         FROM campaign_techniques ct JOIN techniques t ON t.id = ct.technique_id
         WHERE ct.campaign_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT sw.id, sw.attack_id AS "attackId", sw.name
         FROM campaign_software cs JOIN attack_software sw ON sw.id = cs.software_id
         WHERE cs.campaign_id = $1`,
        [entity.id],
      ),
      query<{ id: string; attackId: string; name: string }>(
        `SELECT tg.id, tg.attack_id AS "attackId", tg.name
         FROM group_campaigns gc JOIN threat_groups tg ON tg.id = gc.group_id
         WHERE gc.campaign_id = $1`,
        [entity.id],
      ),
    ]);

    for (const r of techRes.rows)  { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of softRes.rows)  { if (addNode({ id: r.id, label: r.name, type: 'software',  attackId: r.attackId })) edges.push({ source: entity.id, target: r.id, relationship: 'uses' }); }
    for (const r of groupRes.rows) { if (addNode({ id: r.id, label: r.name, type: 'group',     attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'attributed_to' }); }
  }

  else if (entity.type === 'tactic') {
    const techRes = await query<{ id: string; attackId: string; name: string }>(
      `SELECT t.id, t.attack_id AS "attackId", t.name
       FROM technique_tactics tt JOIN techniques t ON t.id = tt.technique_id
       WHERE tt.tactic_id = $1
         AND t.is_subtechnique = false AND t.is_revoked = false AND t.is_deprecated = false
       LIMIT $2`,
      [entity.id, nodeLimit],
    );
    for (const r of techRes.rows) { if (addNode({ id: r.id, label: r.name, type: 'technique', attackId: r.attackId })) edges.push({ source: r.id, target: entity.id, relationship: 'belongs_to' }); }
  }

  const truncated = nodes.length >= nodeLimit;

  res.status(200).json({ center, nodes, edges, truncated });
}

export default withHandler(handler, { cacheTtl: 3600 });
