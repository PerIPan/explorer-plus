import type { VercelRequest, VercelResponse } from '@vercel/node';
import { query } from '../lib/db.js';
import { withHandler } from '../lib/middleware.js';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const { cveId } = req.query;
  const id = Array.isArray(cveId) ? cveId[0] : cveId ?? '';

  if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id)) {
    res.status(400).json({ error: 'Invalid CVE ID', code: 'VALIDATION_ERROR' });
    return;
  }

  // Get NVD metadata
  const detailResult = await query<{
    cve_id: string;
    description: string | null;
    cvss_score: string | null;
    cvss_severity: string | null;
    cvss_vector: string | null;
    cwe_id: string | null;
    published_at: string | null;
  }>(
    `SELECT cve_id, description, cvss_score, cvss_severity, cvss_vector, cwe_id, published_at
     FROM cve_details WHERE cve_id = $1`,
    [id],
  );

  // Get sources from ioc_entries
  const sourcesResult = await query<{ source: string; source_ref: string | null }>(
    `SELECT DISTINCT source, source_ref FROM ioc_entries WHERE type = 'cve' AND value = $1`,
    [id],
  );

  if (!detailResult.rows[0] && !sourcesResult.rows.length) {
    res.status(404).json({ error: 'CVE not found', code: 'NOT_FOUND' });
    return;
  }

  const detail = detailResult.rows[0];

  // Get linked techniques
  const techResult = await query<{
    attack_id: string;
    name: string;
    tactics: string;
  }>(
    `SELECT DISTINCT t.attack_id, t.name,
       COALESCE(
         (SELECT STRING_AGG(DISTINCT tac.name, ', ')
          FROM technique_tactics tt
          JOIN tactics tac ON tac.id = tt.tactic_id
          WHERE tt.technique_id = t.id), ''
       ) AS tactics
     FROM techniques t
     JOIN technique_iocs ti ON ti.technique_id = t.id
     JOIN ioc_entries i ON i.id = ti.ioc_id
     WHERE i.type = 'cve' AND i.value = $1
     ORDER BY t.attack_id`,
    [id],
  );

  // Get related reports (indirect: CVE → techniques → reports)
  const reportsResult = await query<{
    id: string;
    title: string;
    url: string | null;
    source: string | null;
    published_at: string | null;
  }>(
    `SELECT DISTINCT r.id, r.title, r.url, r.source, r.published_at
     FROM threat_reports r
     JOIN report_techniques rt ON rt.report_id = r.id
     JOIN technique_iocs ti ON ti.technique_id = rt.technique_id
     JOIN ioc_entries i ON i.id = ti.ioc_id
     WHERE i.type = 'cve' AND i.value = $1
     ORDER BY r.published_at DESC NULLS LAST
     LIMIT 20`,
    [id],
  );

  res.status(200).json({
    cveId: id,
    description: detail?.description ?? null,
    cvssScore: detail?.cvss_score ? parseFloat(detail.cvss_score) : null,
    cvssSeverity: detail?.cvss_severity ?? null,
    cvssVector: detail?.cvss_vector ?? null,
    cweId: detail?.cwe_id ?? null,
    publishedAt: detail?.published_at ?? null,
    sources: sourcesResult.rows.map((r) => ({
      source: r.source,
      sourceRef: r.source_ref,
    })),
    techniques: techResult.rows.map((r) => ({
      attackId: r.attack_id,
      name: r.name,
      tactics: r.tactics ? r.tactics.split(', ') : [],
    })),
    reports: reportsResult.rows.map((r) => ({
      id: r.id,
      title: r.title,
      url: r.url,
      source: r.source,
      publishedAt: r.published_at,
    })),
  });
}

export default withHandler(handler, { cacheTtl: 300 });
