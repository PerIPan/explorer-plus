import { cache } from 'react';
import { query } from '../api/v1/lib/db';

/**
 * Server-side data fetch utilities wrapped with React cache().
 * Used by generateMetadata and page server components for SSR.
 * Each function fetches the minimal fields needed for metadata generation.
 */

export const fetchTechnique = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM techniques WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchGroup = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM threat_groups WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchCampaign = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM campaigns WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchSoftware = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM attack_software WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchMitigation = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM mitigations WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchTactic = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM tactics WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchDataSource = cache(async (attackId: string) => {
  const result = await query<{ attack_id: string; name: string; description: string | null }>(
    'SELECT attack_id, name, description FROM data_sources WHERE attack_id = $1',
    [attackId],
  );
  return result.rows[0] ?? null;
});

export const fetchSector = cache(async (slug: string) => {
  const result = await query<{ slug: string; name: string }>(
    'SELECT slug, name FROM sectors WHERE slug = $1',
    [slug],
  );
  return result.rows[0] ?? null;
});

export const fetchCve = cache(async (cveId: string) => {
  const result = await query<{ cve_id: string; description: string | null }>(
    'SELECT cve_id, description FROM cve_details WHERE cve_id = $1',
    [cveId],
  );
  return result.rows[0] ?? null;
});

export const fetchOwaspCategory = cache(async (categoryId: string) => {
  const result = await query<{
    category_id: string;
    name: string;
    description: string | null;
    framework: string;
  }>(
    'SELECT category_id, name, description, framework FROM owasp_top10 WHERE UPPER(category_id) = UPPER($1)',
    [categoryId],
  );
  return result.rows[0] ?? null;
});

export const fetchCsfSubcategory = cache(async (subcategoryId: string) => {
  const result = await query<{
    subcategory_id: string;
    name: string;
    description: string | null;
    function: string;
    function_name: string;
    category_name: string;
  }>(
    `SELECT subcategory_id, name, description, function, function_name, category_name
     FROM csf_subcategories
     WHERE subcategory_id = $1 AND version = '2.0'`,
    [subcategoryId.toUpperCase()],
  );
  return result.rows[0] ?? null;
});

/** One D3FEND countermeasure's name and tactic — for /frameworks/d3fend/[d3fendId] metadata and its 404. */
export const fetchD3fendCountermeasure = cache(async (d3fendId: string) => {
  const result = await query<{ d3fend_id: string; name: string | null; tactic: string | null }>(
    `SELECT d3fend_id, MIN(d3fend_name) AS name, MIN(d3fend_tactic) AS tactic
     FROM defensive_mappings
     WHERE d3fend_id = $1
     GROUP BY d3fend_id`,
    [d3fendId.toUpperCase()],
  );
  return result.rows[0] ?? null;
});

/**
 * One compliance framework's name, blurb, tier and whether it maps anything —
 * for /compliance/[key] metadata and its not-found decision. Both lookups are
 * primary-key reads (scf_frameworks, scf_framework_coverage).
 */
export const fetchComplianceFramework = cache(async (key: string) => {
  const result = await query<{ framework_key: string; name: string; short_blurb: string | null; tier: number; scf_controls: number }>(
    `SELECT f.framework_key, f.name, f.short_blurb, f.tier, COALESCE(c.scf_controls, 0)::int AS scf_controls
     FROM scf_frameworks f
     LEFT JOIN scf_framework_coverage c USING (framework_key)
     WHERE f.framework_key = $1`,
    [key],
  );
  return result.rows[0] ?? null;
});
