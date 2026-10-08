import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

/* scripts/migrate-ai-rmf-tier.sql writes, to production, the values the next
 * SCF ingest will write from src/lib/scf-framework-registry.ts. If the two
 * drift, the ingest silently reverts the migration. Read as TEXT (node --test
 * does not import .ts here, as scripts/check-api-catalog.mjs explains), so the
 * regexes are strict: a reformatted entry fails loudly instead of matching
 * nothing. */

const read = (p) => readFileSync(new URL(`../../${p}`, import.meta.url), 'utf8');

const FIELDS = ['name', 'version', 'source_org', 'upstream_url', 'region', 'license', 'short_blurb'];

function registryEntry(src, key) {
  const start = src.indexOf(`framework_key: '${key}',`);
  assert.ok(start > 0, `registry entry ${key} not found`);
  const body = src.slice(start, src.indexOf('\n  },', start));
  const out = {};
  for (const f of FIELDS) {
    const m = body.match(new RegExp(`\\n\\s+${f}: '((?:[^'\\\\]|\\\\.)*)',`));
    assert.ok(m, `${key}.${f} not found as a one-line string literal`);
    out[f] = m[1].replace(/\\'/g, "'");
  }
  const tier = body.match(/\n\s+tier: (\d),/);
  assert.ok(tier, `${key}.tier not found`);
  out.tier = Number(tier[1]);
  return out;
}

function sqlTuple(src, key) {
  // Only inside the VALUES list — the preflight's IN (...) names the keys too.
  const valuesAt = src.indexOf('FROM (VALUES');
  const valuesEnd = src.indexOf('\n  ) AS v(', valuesAt);
  assert.ok(valuesAt > 0 && valuesEnd > valuesAt, 'VALUES block not found');
  const block = src.slice(valuesAt, valuesEnd);
  const start = block.indexOf(`('${key}',`);
  assert.ok(start > 0, `SQL tuple for ${key} not found`);
  const next = block.indexOf('\n    (', start + 1);
  const tuple = block.slice(start, next > 0 ? next : block.length);
  // Values in order: key, name, version, source_org, upstream_url, region, tier, license, short_blurb.
  const strings = [...tuple.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1].replace(/''/g, "'"));
  const tier = tuple.match(/,\s*(\d)\s*,/);
  assert.ok(tier, `${key}: tier literal not found`);
  const [, name, version, source_org, upstream_url, region, license, short_blurb] = strings;
  return { name, version, source_org, upstream_url, region, license, short_blurb, tier: Number(tier[1]) };
}

for (const key of ['nist-ai-rmf', 'nist-600-1-gen-ai-profile']) {
  test(`migrate-ai-rmf-tier.sql matches the registry for ${key}`, () => {
    const reg = registryEntry(read('src/lib/scf-framework-registry.ts'), key);
    const sql = sqlTuple(read('scripts/migrate-ai-rmf-tier.sql'), key);
    assert.deepEqual(sql, reg);
  });
}
