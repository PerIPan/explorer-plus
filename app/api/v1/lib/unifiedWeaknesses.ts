import { query } from './db';

// Process-level cache. On Vercel serverless, each lambda cold-start reruns
// the check once. `to_regclass` against the catalog is sub-millisecond, so
// the overhead is negligible. Cache does not survive view drop/rollback —
// operator should redeploy to invalidate.
let _unifiedViewExists: boolean | null = null;

/**
 * Returns true if the `unified_weaknesses` view exists in the database.
 *
 * Use to branch between the unified query path (preferred) and a legacy
 * cve-only fallback, so pre-migration environments don't 500.
 */
export async function hasUnifiedWeaknessesView(): Promise<boolean> {
  if (_unifiedViewExists !== null) return _unifiedViewExists;
  try {
    const r = await query<{ exists: boolean }>(
      `SELECT to_regclass('public.unified_weaknesses') IS NOT NULL AS exists`,
    );
    _unifiedViewExists = Boolean(r.rows[0]?.exists);
  } catch {
    _unifiedViewExists = false;
  }
  return _unifiedViewExists;
}
