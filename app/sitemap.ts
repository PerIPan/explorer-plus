import type { MetadataRoute } from 'next';
import { query } from './api/v1/lib/db';
import { SITE_URL as BASE_URL } from '../src/lib/site';
import { ECOSYSTEM_REGISTRY } from '../src/lib/ecosystems';

// Force dynamic rendering so the sitemap hits the DB at request time, not at
// build time (when POSTGRES_URL may be unavailable — building static here would
// drop every dynamic URL until revalidation). Keeps the sitemap complete for
// crawlers; the per-crawler DB cost is bounded (sitemap is fetched rarely).
export const dynamic = 'force-dynamic';
export const revalidate = 3600;

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  // '/search' is deliberately ABSENT: app/robots.ts disallows it, and a URL that
  // is both submitted and blocked is reported by Search Console as an error.
  // '/relationships' is absent too — it is a redirect to '/', and sitemaps
  // should list destinations, not hops.
  const staticPages = [
    '', '/dashboard', '/matrix', '/techniques', '/groups', '/campaigns',
    '/software', '/mitigations', '/tactics', '/sectors', '/applications',
    '/assets', '/packages', '/ecosystems', '/profile',
    '/cti/cves', '/cti/reports', '/cti/iocs', '/cti/sigma',
    '/cti/advisories', '/cti/ghsa', '/cti/capec',
    '/cti/feed-status', '/frameworks/owasp', '/frameworks/csf', '/frameworks/nist',
    '/frameworks/iso27001', '/frameworks/engage', '/frameworks/react', '/frameworks/veris',
    '/frameworks/cloud', '/frameworks/atomic', '/frameworks/detection', '/frameworks/d3fend',
    '/frameworks/purdue', '/frameworks/cra', '/frameworks/owasp-ai',
    '/compliance', '/external-actors', '/data-sources', '/about/attributions',
    '/open-apis', '/open-mcp',
  ].map((path) => ({ url: `${BASE_URL}${path}`, changeFrequency: 'weekly' as const }));

  try {
    const [techniques, groups, cves, owasp, csf, frameworks, software, campaigns, mitigations, dataSources, assets, tactics, sectors, capec] = await Promise.all([
      query<{ attack_id: string }>('SELECT attack_id FROM techniques WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM threat_groups WHERE attack_id IS NOT NULL'),
      query<{ cve_id: string }>("SELECT cve_id FROM cve_details WHERE cve_id IS NOT NULL ORDER BY published_at DESC NULLS LAST LIMIT 5000"),
      query<{ category_id: string }>('SELECT category_id FROM owasp_top10'),
      query<{ subcategory_id: string }>("SELECT subcategory_id FROM csf_subcategories WHERE version = '2.0'"),
      query<{ framework_key: string }>('SELECT framework_key FROM scf_frameworks WHERE tier <= 2'),
      query<{ attack_id: string }>('SELECT attack_id FROM attack_software WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM campaigns WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM mitigations WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM data_sources WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM attack_assets WHERE attack_id IS NOT NULL'),
      query<{ attack_id: string }>('SELECT attack_id FROM tactics WHERE attack_id IS NOT NULL'),
      query<{ slug: string }>('SELECT slug FROM sectors WHERE slug IS NOT NULL'),
      query<{ id: number }>('SELECT id FROM capec_patterns'),
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

    // Entity types that had list pages in the sitemap but whose DETAIL pages were
    // never listed — every one of these is a real, linked, indexable page that
    // Google could only find by crawling, not by submission.
    const simple = (rows: { attack_id: string }[], seg: string) =>
      rows.map((r) => ({
        url: `${BASE_URL}/${seg}/${r.attack_id}`,
        changeFrequency: 'monthly' as const,
      }));

    const dataSourceUrls = simple(dataSources.rows, 'data-sources');
    const assetUrls = simple(assets.rows, 'assets');
    const tacticUrls = simple(tactics.rows, 'tactics');

    const sectorUrls = sectors.rows.map((s) => ({
      url: `${BASE_URL}/sectors/${s.slug}`,
      changeFrequency: 'monthly' as const,
    }));

    // CAPEC's canonical URL form is the prefixed id the API returns.
    const capecUrls = capec.rows.map((c) => ({
      url: `${BASE_URL}/cti/capec/CAPEC-${c.id}`,
      changeFrequency: 'monthly' as const,
    }));

    // From the registry the /ecosystems/<slug> route itself resolves through,
    // so a listed URL cannot 404.
    const ecosystemUrls = Array.from(ECOSYSTEM_REGISTRY.keys()).map((slug) => ({
      url: `${BASE_URL}/ecosystems/${slug}`,
      changeFrequency: 'weekly' as const,
    }));

    return [
      ...staticPages, ...techniqueUrls, ...groupUrls, ...cveUrls, ...owaspUrls,
      ...csfUrls, ...complianceUrls, ...softwareUrls, ...campaignUrls, ...mitigationUrls,
      ...dataSourceUrls, ...assetUrls, ...tacticUrls, ...sectorUrls, ...capecUrls,
      ...ecosystemUrls,
    ];
  } catch (err) {
    // If DB is not available (e.g., build time), return static pages only
    console.error('[sitemap] DB query failed, returning static pages only:', err);
    return staticPages;
  }
}
