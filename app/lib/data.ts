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
