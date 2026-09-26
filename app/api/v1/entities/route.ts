import { NextRequest } from 'next/server';
import { query } from '../lib/db';
import { jsonResponse } from '../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../lib/cors';
import { domainSchema } from '../lib/validate';
import { z } from 'zod';
import { ECOSYSTEM_REGISTRY } from '../../../../src/lib/ecosystems';
import { SCF_FRAMEWORK_REGISTRY } from '../../../../src/lib/scf-framework-registry';

export { OPTIONS };

const querySchema = z.object({
  domain: domainSchema,
});

/**
 * Lightweight endpoint returning all entity names + IDs for client-side fuzzy search.
 * Cached aggressively — data only changes on re-seed.
 */
export async function GET(req: NextRequest) {
  const rawParams: Record<string, string> = {};
  req.nextUrl.searchParams.forEach((v, k) => { rawParams[k] = v; });

  const parsed = querySchema.safeParse(rawParams);
  const domain = parsed.success ? parsed.data.domain ?? null : null;

  // Two forms: techniques, mitigations and tactics hold domain as a scalar
  // varchar, while attack_software and campaigns hold text[] (an entity can
  // belong to several domains). Equality against the array columns makes
  // Postgres parse the scalar as an array literal and raise 22P02 — which
  // 500'd this endpoint, and with it the search bar, whenever a domain was set.
  const domainWhere = domain ? ` AND domain = $1` : '';
  const domainArrayWhere = domain ? ` AND $1 = ANY(domain)` : '';
  const domainParams = domain ? [domain] : [];

  const [techniques, groups, software, campaigns, mitigations, tactics, externalActors, sectors, applications, owaspCategories, csfSubcategories, dataSources, assets] = await Promise.all([
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
       WHERE is_revoked = false AND is_deprecated = false${domainArrayWhere}
       ORDER BY name`,
      domainParams,
    ),
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM campaigns
       WHERE is_revoked = false AND is_deprecated = false${domainArrayWhere}
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
    // Sectors are not domain-scoped
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT slug AS "attackId", name, NULL as domain FROM sectors WHERE slug IS NOT NULL ORDER BY name
    `),
    // Applications — top 500 by CVE count for search
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT normalized AS "attackId", vendor || ' / ' || product AS name, NULL as domain
      FROM applications WHERE cve_count > 0 ORDER BY cve_count DESC LIMIT 500
    `),
    // OWASP categories — all frameworks
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT category_id AS "attackId", category_id || ' ' || name AS name, NULL as domain
      FROM owasp_top10 ORDER BY framework, category_id
    `),
    // CSF v2 subcategories
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT subcategory_id AS "attackId", subcategory_id || ' ' || name AS name, NULL as domain
      FROM csf_subcategories WHERE version = '2.0' ORDER BY function, subcategory_id
    `),
    // Data sources. These have a detail page and the server-side /search
    // endpoint already returns them, so their absence here meant the header
    // dropdown and the full search page disagreed about what exists.
    // `data_sources.domain` is a scalar varchar, like techniques.
    query<{ attackId: string; name: string; domain: string | null }>(
      `SELECT attack_id AS "attackId", name, domain FROM data_sources${domainWhere}
       ORDER BY name`,
      domainParams,
    ),
    // ATT&CK for ICS assets (A0001-A0018). Carries the ics-attack domain so the
    // domain filter treats them like any other ICS entity.
    query<{ attackId: string; name: string; domain: string | null }>(`
      SELECT attack_id AS "attackId", name, 'ics-attack' AS domain
      FROM attack_assets
      WHERE is_revoked = false AND is_deprecated = false
      ORDER BY name
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
    ...sectors.rows.map(r => ({ ...r, type: 'sector' })),
    ...applications.rows.map(r => ({ ...r, type: 'application' })),
    ...owaspCategories.rows.map(r => ({ ...r, type: 'owasp' })),
    ...csfSubcategories.rows.map(r => ({ ...r, type: 'csf' })),
    ...assets.rows.map(r => ({ ...r, type: 'asset' })),
    ...dataSources.rows.map(r => ({ ...r, type: 'data_source' })),
    // Not domain-scoped: an ecosystem (npm, PyPI) and a compliance framework
    // are properties of the software supply chain and of governance, not of an
    // ATT&CK matrix. Sourced from the registries the detail routes resolve
    // through, so a hit here can never 404.
    ...Array.from(ECOSYSTEM_REGISTRY.values()).map(e => ({
      attackId: e.slug, name: e.displayName, domain: null, type: 'ecosystem',
    })),
    ...SCF_FRAMEWORK_REGISTRY.map(f => ({
      attackId: f.framework_key, name: f.name, domain: null, type: 'compliance',
    })),
  ];

  return withCors(jsonResponse({ data: entities, total: entities.length }, 86400));
}
