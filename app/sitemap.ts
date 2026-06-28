import type { MetadataRoute } from 'next';
import { query } from './api/v1/lib/db';

// Force dynamic rendering so the sitemap hits the DB at request time,
// not at build time (when POSTGRES_URL may be unavailable).
export const dynamic = 'force-dynamic';
export const revalidate = 3600;

const BASE_URL = 'https://mitre-explorer.org';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticPages = [
    '', '/dashboard', '/matrix', '/techniques', '/groups', '/campaigns',
    '/software', '/mitigations', '/tactics', '/sectors', '/applications',
    '/search', '/cti/cves', '/cti/reports', '/cti/iocs', '/cti/sigma',
    '/cti/feed-status', '/frameworks/owasp', '/frameworks/csf', '/frameworks/nist',
    '/frameworks/engage', '/frameworks/react', '/frameworks/veris',
    '/frameworks/cloud', '/frameworks/atomic', '/frameworks/detection',
    '/compliance', '/external-actors', '/data-sources',
  ].map((path) => ({ url: `${BASE_URL}${path}`, changeFrequency: 'weekly' as const }));

  try {
    const [techniques, groups, cves, owasp, csf, frameworks, software, campaigns, mitigations] = await Promise.all([
      query<{ attack_id: string }>('SELECT attack_id FROM techniques WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM threat_groups WHERE attack_id IS NOT NULL'),
      query<{ cve_id: string }>("SELECT cve_id FROM cve_details WHERE cve_id IS NOT NULL ORDER BY published_at DESC NULLS LAST LIMIT 5000"),
      query<{ category_id: string }>('SELECT category_id FROM owasp_top10'),
      query<{ subcategory_id: string }>("SELECT subcategory_id FROM csf_subcategories WHERE version = '2.0'"),
      query<{ framework_key: string }>('SELECT framework_key FROM scf_frameworks WHERE tier <= 2'),
      query<{ attack_id: string }>('SELECT attack_id FROM attack_software WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM campaigns WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM mitigations WHERE attack_id IS NOT NULL'),
    ]);

    const techniqueUrls = techniques.rows.map((t) => ({
      url: `${BASE_URL}/techniques/${t.attack_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const groupUrls = groups.rows.map((g) => ({
      url: `${BASE_URL}/groups/${g.attack_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const cveUrls = cves.rows.map((c) => ({
      url: `${BASE_URL}/cti/cves/${c.cve_id}`,
      changeFrequency: 'weekly' as const,
    }));

    const owaspUrls = owasp.rows.map((o) => ({
      url: `${BASE_URL}/frameworks/owasp/${o.category_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const csfUrls = csf.rows.map((c) => ({
      url: `${BASE_URL}/frameworks/csf/${c.subcategory_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const complianceUrls = frameworks.rows.map((f) => ({
      url: `${BASE_URL}/compliance/${f.framework_key}`,
      changeFrequency: 'monthly' as const,
    }));

    const softwareUrls = software.rows.map((s) => ({
      url: `${BASE_URL}/software/${s.attack_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const campaignUrls = campaigns.rows.map((c) => ({
      url: `${BASE_URL}/campaigns/${c.attack_id}`,
      changeFrequency: 'monthly' as const,
    }));

    const mitigationUrls = mitigations.rows.map((m) => ({
      url: `${BASE_URL}/mitigations/${m.attack_id}`,
      changeFrequency: 'monthly' as const,
    }));

    return [
      ...staticPages, ...techniqueUrls, ...groupUrls, ...cveUrls, ...owaspUrls,
      ...csfUrls, ...complianceUrls, ...softwareUrls, ...campaignUrls, ...mitigationUrls,
    ];
  } catch (err) {
    // If DB is not available (e.g., build time), return static pages only
    console.error('[sitemap] DB query failed, returning static pages only:', err);
    return staticPages;
  }
}
