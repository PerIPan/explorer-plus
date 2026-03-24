import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../../lib/db.js';
import { withHandler } from '../../lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const { attackId } = req.query;
  const id = Array.isArray(attackId) ? attackId[0] : attackId ?? '';

  if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) {
    res.status(400).json({ error: 'Invalid ATT&CK ID', code: 'VALIDATION_ERROR' });
    return;
  }

  // Look up technique DB id (UUID)
  const techResult = await query<{ id: string }>(
    'SELECT id FROM techniques WHERE attack_id = $1 LIMIT 1',
    [id],
  );

  if (!techResult.rows[0]) {
    res.status(404).json({ error: 'Technique not found', code: 'NOT_FOUND' });
    return;
  }

  const techId = techResult.rows[0].id;

  const [reportsResult, sigmaResult, atomicResult, defensiveResult, iocsResult] =
    await Promise.all([
      // Top 5 threat reports
      query<{
        id: string;
        title: string;
        url: string | null;
        source: string | null;
        published_at: string | null;
      }>(
        `SELECT r.id, r.title, r.url, r.source, r.published_at
         FROM threat_reports r
         JOIN report_techniques rt ON rt.report_id = r.id
         WHERE rt.technique_id = $1
         ORDER BY r.published_at DESC NULLS LAST
         LIMIT 5`,
        [techId],
      ),

      // Sigma rules
      query<{
        id: string;
        sigma_id: string | null;
        title: string;
        level: string | null;
        status: string | null;
        logsource_category: string | null;
        logsource_product: string | null;
      }>(
        `SELECT id, sigma_id, title, level, status, logsource_category, logsource_product
         FROM sigma_rules
         WHERE technique_id = $1
         ORDER BY
           CASE level
             WHEN 'critical' THEN 1 WHEN 'high' THEN 2
             WHEN 'medium' THEN 3 WHEN 'low' THEN 4
             ELSE 5 END, title ASC`,
        [techId],
      ),

      // Atomic tests — include sub-technique tests when viewing parent
      query<{
        id: string;
        test_number: number;
        name: string;
        description: string | null;
        platforms: string[] | null;
        executor_type: string | null;
      }>(
        `SELECT a.id, a.test_number, a.name, a.description, a.platforms, a.executor_type
         FROM atomic_tests a
         WHERE a.technique_id = $1
            OR a.technique_id IN (SELECT id FROM techniques WHERE parent_technique_id = $1)
         ORDER BY a.test_number ASC`,
        [techId],
      ),

      // D3FEND mappings — d3fend_name is the label column
      query<{
        id: string;
        d3fend_id: string;
        d3fend_label: string | null;
        d3fend_tactic: string | null;
      }>(
        `SELECT id, d3fend_id, d3fend_name AS d3fend_label, d3fend_tactic
         FROM defensive_mappings
         WHERE technique_id = $1
         ORDER BY d3fend_name ASC`,
        [techId],
      ),

      // Top 10 IOCs
      query<{
        id: string;
        type: string;
        value: string;
        source: string | null;
        malware_family: string | null;
        first_seen: string | null;
        description: string | null;
        confidence: string;
        vt_malicious: number | null;
        vt_total: number | null;
        vt_verdict: string | null;
      }>(
        `SELECT
           i.id, i.type, i.value, i.source, i.malware_family, i.first_seen,
           i.description, ti.confidence, i.vt_malicious, i.vt_total, i.vt_verdict
         FROM ioc_entries i
         JOIN technique_iocs ti ON ti.ioc_id = i.id
         WHERE ti.technique_id = $1
         ORDER BY
           CASE ti.confidence WHEN 'sandbox_verified' THEN 1 WHEN 'inferred' THEN 2 ELSE 3 END,
           i.first_seen DESC NULLS LAST
         LIMIT 10`,
        [techId],
      ),
    ]);

  // Normalize ioc first_seen → first_seen_at for frontend
  const iocs = iocsResult.rows.map((r) => ({
    ...r,
    first_seen_at: r.first_seen,
  }));

  res.status(200).json({
    attackId: id,
    reports: reportsResult.rows,
    sigmaRules: sigmaResult.rows,
    atomicTests: atomicResult.rows,
    defensiveMappings: defensiveResult.rows,
    iocs,
  });
}

export default withHandler(handler, { cacheTtl: 300 });
