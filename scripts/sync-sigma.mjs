/**
 * sync-sigma.mjs
 * Recursively scans /tmp/sigma/rules/ for Sigma YAML files,
 * parses each one, and upserts into the sigma_rules table.
 *
 * Usage: node scripts/sync-sigma.mjs
 * Requires: DATABASE_URL env var, pg installed
 */

import { readdir, readFile, stat } from 'fs/promises';
import { join } from 'path';
import pkg from 'pg';

const { Pool } = pkg;

const SIGMA_ROOT = '/tmp/sigma/rules';
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

/**
 * Minimal YAML parser for Sigma rule structure.
 * Handles top-level scalar fields and simple arrays.
 */
function parseSigmaYaml(text) {
  const lines = text.split('\n');
  const result = {};
  let currentKey = null;
  let inLogsource = false;
  const logsource = {};

  for (const raw of lines) {
    const trimmed = raw.trimEnd();

    // Top-level key: value (no leading whitespace)
    const topLevel = trimmed.match(/^([a-zA-Z_][a-zA-Z0-9_]*):\s*(.*)$/);
    if (topLevel && !/^\s/.test(raw)) {
      currentKey = topLevel[1];
      const val = topLevel[2].trim();
      inLogsource = currentKey === 'logsource';

      if (inLogsource) {
        result.logsource = logsource;
      } else if (val === '' || val === '|') {
        result[currentKey] = null;
      } else if (val.startsWith('[')) {
        result[currentKey] = val
          .replace(/^\[/, '')
          .replace(/\]$/, '')
          .split(',')
          .map((s) => s.trim().replace(/^['"]|['"]$/g, ''))
          .filter(Boolean);
      } else {
        result[currentKey] = val.replace(/^['"]|['"]$/g, '');
      }
      continue;
    }

    // Logsource child
    if (inLogsource) {
      const lsMatch = trimmed.match(/^\s+([a-zA-Z_]+):\s*(.+)$/);
      if (lsMatch) {
        logsource[lsMatch[1]] = lsMatch[2].trim().replace(/^['"]|['"]$/g, '');
        continue;
      }
      if (trimmed && !/^\s/.test(raw)) inLogsource = false;
    }

    // Array item
    const arrayItem = trimmed.match(/^\s+- (.+)$/);
    if (arrayItem && currentKey && !inLogsource) {
      const val = arrayItem[1].trim().replace(/^['"]|['"]$/g, '');
      if (!Array.isArray(result[currentKey])) {
        result[currentKey] = result[currentKey] ? [result[currentKey]] : [];
      }
      result[currentKey].push(val);
    }
  }

  return result;
}

/** Normalize Sigma attack tag to ATT&CK ID: 'attack.t1059.001' → 'T1059.001' */
function normalizeAttackTag(tag) {
  const m = tag.match(/^attack\.(t\d{4}(?:\.\d{3})?)$/i);
  if (!m) return null;
  // Ensure sub-technique separator has no leading zero: .001 stays .001
  return m[1].toUpperCase();
}

async function findYamlFiles(dir) {
  const results = [];
  let entries;
  try {
    entries = await readdir(dir);
  } catch {
    return results;
  }

  for (const entry of entries) {
    const full = join(dir, entry);
    const info = await stat(full).catch(() => null);
    if (!info) continue;

    if (info.isDirectory()) {
      const sub = await findYamlFiles(full);
      results.push(...sub);
    } else if (entry.endsWith('.yml') || entry.endsWith('.yaml')) {
      results.push(full);
    }
  }
  return results;
}

async function main() {
  const client = await pool.connect();
  let inserted = 0;
  let updated = 0;
  let errors = 0;

  try {
    const files = await findYamlFiles(SIGMA_ROOT);
    console.log(`Found ${files.length} Sigma YAML files`);

    for (const file of files) {
      try {
        const text = await readFile(file, 'utf-8');
        const rule = parseSigmaYaml(text);

        if (!rule.id || !rule.title) continue;

        const tags = Array.isArray(rule.tags) ? rule.tags : [];
        const attackIds = tags.map(normalizeAttackTag).filter(Boolean);

        // Take first matching technique
        let techniqueId = null;
        let attackTechniqueId = null;

        for (const aid of attackIds) {
          const r = await client.query(
            'SELECT id FROM techniques WHERE attack_id = $1 LIMIT 1',
            [aid],
          );
          if (r.rows[0]) {
            techniqueId = r.rows[0].id;
            attackTechniqueId = aid;
            break;
          }
        }

        // If no DB match but we parsed an attack ID, store the text anyway
        if (!attackTechniqueId && attackIds.length > 0) {
          attackTechniqueId = attackIds[0];
        }

        const ls = rule.logsource ?? {};

        // sigma_rules has no raw_yaml column — omit it
        const res = await client.query(
          `INSERT INTO sigma_rules
             (sigma_id, title, technique_id, attack_technique_id,
              level, status, logsource_category, logsource_product)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (sigma_id) DO UPDATE
             SET title = EXCLUDED.title,
                 technique_id = EXCLUDED.technique_id,
                 attack_technique_id = EXCLUDED.attack_technique_id,
                 level = EXCLUDED.level,
                 status = EXCLUDED.status,
                 logsource_category = EXCLUDED.logsource_category,
                 logsource_product = EXCLUDED.logsource_product,
                 updated_at = NOW()
           RETURNING (xmax = 0) AS was_inserted`,
          [
            rule.id,
            rule.title,
            techniqueId,
            attackTechniqueId,
            rule.level ?? null,
            rule.status ?? null,
            ls.category ?? null,
            ls.product ?? null,
          ],
        );

        if (res.rows[0]?.was_inserted) inserted++; else updated++;
      } catch (fileErr) {
        errors++;
        if (errors <= 10) console.error(`Error processing ${file}:`, fileErr.message);
      }
    }

    console.log(`Sigma sync complete: ${inserted} inserted, ${updated} updated, ${errors} errors`);
  } finally {
    client.release();
    await pool.end();
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
