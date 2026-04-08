import type { MetadataRoute } from 'next';
import { query } from './api/v1/lib/db';

const BASE_URL = 'https://mitre-explorer.org';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticPages = [
    '', '/dashboard', '/matrix', '/techniques', '/groups', '/campaigns',
    '/software', '/mitigations', '/tactics', '/sectors', '/applications',
    '/search', '/cti/cves', '/cti/reports', '/cti/iocs', '/cti/sigma',
    '/cti/feed-status', '/frameworks/owasp', '/frameworks/nist',
    '/frameworks/engage', '/frameworks/react', '/frameworks/veris',
    '/frameworks/cloud', '/frameworks/atomic', '/frameworks/detection',
    '/external-actors', '/data-sources',
  ].map((path) => ({ url: `${BASE_URL}${path}`, changeFrequency: 'weekly' as const }));

  try {
    const [techniques, groups, cves] = await Promise.all([
      query<{ attack_id: string }>('SELECT attack_id FROM techniques WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM threat_groups WHERE attack_id IS NOT NULL'),
      query<{ cve_id: string }>("SELECT cve_id FROM cves WHERE cve_id IS NOT NULL ORDER BY published_at DESC NULLS LAST LIMIT 5000"),
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

    return [...staticPages, ...techniqueUrls, ...groupUrls, ...cveUrls];
  } catch {
    // If DB is not available (e.g., build time), return static pages only
    return staticPages;
  }
}
