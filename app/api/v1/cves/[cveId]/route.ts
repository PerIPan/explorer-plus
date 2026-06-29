import { NextRequest } from 'next/server';
import { query } from '../../lib/db';
import { notCatchallCwe } from '../../lib/inference';
import { escapeLikePattern } from '../../lib/queries';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ cveId: string }> }
) {
  const { cveId } = await params;
  const id = cveId ?? '';

  if (!id || !/^CVE-\d{4}-\d{4,}$/.test(id)) {
    return withCors(errorResponse(400, 'Invalid CVE ID', 'VALIDATION_ERROR'));
  }

  // Optional version filter — substring/text match against the affected
  // applications' version_start/version_end. The CVE is the product context,
  // so it's standalone here. Only narrows `affectedApps`.
  const versionRaw = req.nextUrl.searchParams.get('version')?.trim();
  const version = versionRaw ? versionRaw.slice(0, 100) : null;
  const appsWhere = version
    ? 'WHERE ap.cve_id = $1 AND (ap.version_start ILIKE $2 OR ap.version_end ILIKE $2)'
    : 'WHERE ap.cve_id = $1';
  const appsParams = version ? [id, `%${escapeLikePattern(version)}%`] : [id];

  const [detailResult, sourcesResult, cwesResult, appsResult, techIocResult, techCapecResult, reportsResult, owaspResult, ghsaResult, osvRes] =
    await Promise.all([
      query<{
        cve_id: string;
        description: string | null;
        cvss_score: string | null;
        cvss_severity: string | null;
        cvss_vector: string | null;
        cwe_id: string | null;
        published_at: string | null;
        is_kev: boolean;
        epss_score: string | null;
        epss_percentile: string | null;
        epss_updated_at: string | null;
      }>(
        `SELECT cve_id, description, cvss_score, cvss_severity, cvss_vector, cwe_id, published_at,
                COALESCE(is_kev, false) AS is_kev,
                epss_score, epss_percentile, epss_updated_at
         FROM cve_details WHERE cve_id = $1`,
        [id],
      ),

      query<{ source: string; source_ref: string | null }>(
        `SELECT DISTINCT source, source_ref FROM ioc_entries WHERE type = 'cve' AND value = $1`,
        [id],
      ),

      query<{ cwe_id: string }>(
        `SELECT DISTINCT cwe_id FROM cve_weaknesses
         WHERE cve_id = $1 AND cwe_id LIKE 'CWE-%'
         ORDER BY cwe_id`,
        [id],
      ),

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
         ${appsWhere}
         ORDER BY a.cve_count DESC, a.vendor, a.product`,
        appsParams,
      ),

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
           AND ${notCatchallCwe('cm.cwe_id')}
         JOIN techniques t ON t.id = cm.technique_id AND t.is_revoked = false AND t.is_deprecated = false
         WHERE cw.cve_id = $1`,
        [id],
      ),

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
             AND ${notCatchallCwe('cm.cwe_id')}
           WHERE cw.cve_id = $1
         )
         ORDER BY r.published_at DESC NULLS LAST
         LIMIT 20`,
        [id],
      ),

      query<{ categoryId: string; name: string; framework: string }>(
        `SELECT DISTINCT o.category_id AS "categoryId", o.name, o.framework
         FROM owasp_top10 o
         JOIN cve_weaknesses cw ON cw.cwe_id = ANY(o.cwe_ids)
         WHERE cw.cve_id = $1
         ORDER BY o.framework, o.category_id`,
        [id],
      ),

      // Minimal GHSA stub — full details via /api/v1/ghsa/:ghsaId
      // Wrapped in .catch for pre-migration envs where ghsa_advisories may not exist
      query<{ ghsaId: string; summary: string | null }>(
        `SELECT ghsa_id AS "ghsaId", summary
         FROM ghsa_advisories WHERE cve_id = $1 LIMIT 1`,
        [id],
      ).catch(() => ({ rows: [] as Array<{ ghsaId: string; summary: string | null }> })),

      // OSV cross-refs: non-GHSA (OS/distro/kernel) advisories that alias this
      // CVE. GIN-indexed on `aliases` so the `&&` check is cheap. Wrapped in
      // .catch for pre-migration envs without the osv_advisories table.
      query<{
        osvId: string;
        ecosystem: string;
        summary: string | null;
        cvssScore: string | null;
        cvssSeverity: string | null;
        published: string | null;
      }>(
        `SELECT osv_id        AS "osvId",
                ecosystem,
                summary,
                cvss_score    AS "cvssScore",
                cvss_severity AS "cvssSeverity",
                published
         FROM osv_advisories
         WHERE aliases && ARRAY[$1]::text[]
         ORDER BY ecosystem, published DESC NULLS LAST
         LIMIT 25`,
        [id],
      ).catch(() => ({
        rows: [] as Array<{
          osvId: string; ecosystem: string; summary: string | null;
          cvssScore: string | null; cvssSeverity: string | null; published: string | null;
        }>,
      })),
    ]);

  // Resolve CAPEC attack patterns via CWE overlap. Safe on pre-migration envs
  // where capec_patterns may not exist — fall back to empty.
  const capecResult = await query<{
    capecId: string; name: string; severity: string | null; likelihood: string | null; abstraction: string | null;
  }>(
    `SELECT p.id AS "capecId", p.name, p.severity, p.likelihood, p.abstraction
     FROM capec_patterns p
     WHERE p.cwe_ids && (
       SELECT COALESCE(ARRAY_AGG(DISTINCT cwe_id::text), ARRAY[]::text[])
       FROM cve_weaknesses WHERE cve_id = $1 AND cwe_id LIKE 'CWE-%'
     )
     ORDER BY
       CASE p.severity WHEN 'Very High' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3
            WHEN 'Low' THEN 2 WHEN 'Very Low' THEN 1 ELSE 0 END DESC,
       p.id`,
    [id],
  ).catch(() => ({ rows: [] as Array<{ capecId: string; name: string; severity: string | null; likelihood: string | null; abstraction: string | null }> }));

  if (!detailResult.rows[0] && !sourcesResult.rows.length) {
    return withCors(errorResponse(404, 'CVE not found', 'NOT_FOUND'));
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

  return withCors(jsonResponse({
    cveId: id,
    versionFilter: version ?? null,
    description: detail?.description ?? null,
    cvssScore: detail?.cvss_score ? parseFloat(detail.cvss_score) : null,
    cvssSeverity: detail?.cvss_severity ?? null,
    cvssVector: detail?.cvss_vector ?? null,
    epssScore: detail?.epss_score ? parseFloat(detail.epss_score) : null,
    epssPercentile: detail?.epss_percentile ? parseFloat(detail.epss_percentile) : null,
    epssUpdatedAt: detail?.epss_updated_at ?? null,
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
    owaspCategories: owaspResult.rows,
    ghsa: ghsaResult.rows[0] ?? null,
    capecPatterns: capecResult.rows,
    osvAdvisories: osvRes.rows.map((r) => ({
      osvId: r.osvId,
      ecosystem: r.ecosystem,
      summary: r.summary,
      cvssScore: r.cvssScore ? parseFloat(r.cvssScore) : null,
      cvssSeverity: r.cvssSeverity,
      published: r.published,
    })),
  }, 300));
}
