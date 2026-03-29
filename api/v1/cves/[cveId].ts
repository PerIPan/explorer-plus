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

  const [detailResult, sourcesResult, cwesResult, appsResult, techIocResult, techCapecResult, reportsResult] =
    await Promise.all([
      // CVE metadata
      query<{
        cve_id: string;
        description: string | null;
        cvss_score: string | null;
        cvss_severity: string | null;
        cvss_vector: string | null;
        cwe_id: string | null;
        published_at: string | null;
        is_kev: boolean;
      }>(
        `SELECT cve_id, description, cvss_score, cvss_severity, cvss_vector, cwe_id, published_at,
                COALESCE(is_kev, false) AS is_kev
         FROM cve_details WHERE cve_id = $1`,
        [id],
      ),

      // Sources from ioc_entries
      query<{ source: string; source_ref: string | null }>(
        `SELECT DISTINCT source, source_ref FROM ioc_entries WHERE type = 'cve' AND value = $1`,
        [id],
      ),

      // All CWEs (from cve_weaknesses, excluding synthetic CTID entries)
      query<{ cwe_id: string }>(
        `SELECT DISTINCT cwe_id FROM cve_weaknesses
         WHERE cve_id = $1 AND cwe_id LIKE 'CWE-%'
         ORDER BY cwe_id`,
        [id],
      ),

      // Affected applications with version ranges
      query<{
        normalized: string;
        vendor: string;
        product: string;
        version_start: string | null;
        version_end: string | null;
        cve_count: string;
      }>(
        `SELECT a.normalized, a.vendor, a.product,
                ap.version_start, ap.version_end, a.cve_count::text
         FROM affected_products ap
         JOIN applications a ON a.id = ap.application_id
         WHERE ap.cve_id = $1
         ORDER BY a.cve_count DESC, a.vendor, a.product`,
        [id],
      ),

      // Techniques via IOC path (OTX, abuse.ch, CISA KEV)
      query<{ attack_id: string; name: string; tactics: string; source: string }>(
        `SELECT DISTINCT t.attack_id, t.name,
           COALESCE(
             (SELECT STRING_AGG(DISTINCT tac.name, ', ')
              FROM technique_tactics tt
              JOIN tactics tac ON tac.id = tt.tactic_id
              WHERE tt.technique_id = t.id), ''
           ) AS tactics,
           'ioc' AS source
         FROM techniques t
         JOIN technique_iocs ti ON ti.technique_id = t.id
         JOIN ioc_entries i ON i.id = ti.ioc_id
         WHERE i.type = 'cve' AND i.value = $1`,
        [id],
      ),

      // Techniques via CAPEC bridge + CTID (CWE→CAPEC→technique)
      query<{ attack_id: string; name: string; tactics: string; source: string }>(
        `SELECT DISTINCT t.attack_id, t.name,
           COALESCE(
             (SELECT STRING_AGG(DISTINCT tac.name, ', ')
              FROM technique_tactics tt
              JOIN tactics tac ON tac.id = tt.tactic_id
              WHERE tt.technique_id = t.id), ''
           ) AS tactics,
           CASE WHEN cm.capec_id = 'CTID-DIRECT' THEN 'ctid' ELSE 'capec' END AS source
         FROM cve_weaknesses cw
         JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
         JOIN techniques t ON t.id = cm.technique_id
         WHERE cw.cve_id = $1`,
        [id],
      ),

      // Related reports (indirect: CVE → techniques → reports)
      query<{
        id: string;
        title: string;
        url: string | null;
        source: string | null;
        published_at: string | null;
      }>(
        `SELECT DISTINCT r.id, r.title, r.url, r.source, r.published_at
         FROM threat_reports r
         JOIN report_techniques rt ON rt.report_id = r.id
         WHERE rt.technique_id IN (
           SELECT ti.technique_id FROM technique_iocs ti
           JOIN ioc_entries i ON i.id = ti.ioc_id
           WHERE i.type = 'cve' AND i.value = $1
           UNION
           SELECT cm.technique_id FROM cve_weaknesses cw
           JOIN capec_mappings cm ON cm.cwe_id = cw.cwe_id AND cm.technique_id IS NOT NULL
           WHERE cw.cve_id = $1
         )
         ORDER BY r.published_at DESC NULLS LAST
         LIMIT 20`,
        [id],
      ),
    ]);

  if (!detailResult.rows[0] && !sourcesResult.rows.length) {
    res.status(404).json({ error: 'CVE not found', code: 'NOT_FOUND' });
    return;
  }

  const detail = detailResult.rows[0];

  // Merge techniques from both paths, deduplicate by attack_id
  const techMap = new Map<string, { attackId: string; name: string; tactics: string[]; sources: string[] }>();
  for (const r of [...techIocResult.rows, ...techCapecResult.rows]) {
    const existing = techMap.get(r.attack_id);
    if (existing) {
      if (!existing.sources.includes(r.source)) existing.sources.push(r.source);
    } else {
      techMap.set(r.attack_id, {
        attackId: r.attack_id,
        name: r.name,
        tactics: r.tactics ? r.tactics.split(', ') : [],
        sources: [r.source],
      });
    }
  }

  res.status(200).json({
    cveId: id,
    description: detail?.description ?? null,
    cvssScore: detail?.cvss_score ? parseFloat(detail.cvss_score) : null,
    cvssSeverity: detail?.cvss_severity ?? null,
    cvssVector: detail?.cvss_vector ?? null,
    cweId: detail?.cwe_id ?? null,
    cwes: cwesResult.rows.map((r) => r.cwe_id),
    isKev: detail?.is_kev ?? false,
    publishedAt: detail?.published_at ?? null,
    sources: sourcesResult.rows.map((r) => ({
      source: r.source,
      sourceRef: r.source_ref,
    })),
    techniques: Array.from(techMap.values()).sort((a, b) => a.attackId.localeCompare(b.attackId)),
    affectedApps: appsResult.rows.map((r) => ({
      normalized: r.normalized,
      vendor: r.vendor,
      product: r.product,
      versionStart: r.version_start,
      versionEnd: r.version_end,
      cveCount: parseInt(r.cve_count, 10),
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
