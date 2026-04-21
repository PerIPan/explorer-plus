import { NextRequest, NextResponse } from 'next/server';
import JSZip from 'jszip';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const cvss = require('cvss');
import { query } from '../../v1/lib/db';
import { verifyCronAuth } from '../lib/auth';
import { withSoftTimeout } from '../lib/softTimeout';

// OSV runs past the default 270s soft-timeout. We bumped `maxDuration` to
// 800s; give the soft timer 30s headroom inside that so the terminal
// UPDATE to feed_sync_log always lands before Vercel kills the function.
const OSV_SOFT_TIMEOUT_MS = 770_000;

// OSV daily delta touches 33 ecosystems serially — full-corpus zip fetch per
// ecosystem even in delta mode (OSV doesn't publish per-day zips). At the
// 300s default we hit soft timeout on every run processing ~47k records.
// Bumped to 800s (Vercel Pro allows up to 900) so the whole corpus fits.
export const maxDuration = 800;

const OSV_BASE = 'https://osv-vulnerabilities.storage.googleapis.com';
const BATCH_SIZE = 500;

/**
 * Daily cron runs a 7-day delta (records `modified >= NOW() - DELTA_DAYS`).
 * Rolls us forward without rewriting the full corpus every night; absorbs
 * up to 7 consecutive cron failures before data goes stale.
 */
const DELTA_DAYS = 7;

/**
 * Monthly reconcile (mode=full) bypasses the delta and reads the full
 * corpus. Scheduled for the last day of the month via vercel.json — the
 * isLastDayOfMonth() guard turns 28/29/30 runs into no-ops in longer months.
 */
function isLastDayOfMonth(now: Date = new Date()): boolean {
  const t = new Date(now);
  t.setUTCDate(t.getUTCDate() + 1);
  return t.getUTCDate() === 1;
}

/**
 * Ecosystems where GHSA is effectively the source of truth. Our
 * `ghsa_advisories` table already mirrors the reviewed subset OSV re-exports
 * for these, so refetching them would just duplicate storage. GitHub upgrades
 * PYSEC/GO/RUSTSEC/DRUPAL/PSF records to GHSA quickly — what we lose by
 * skipping these zips is minimal and can be measured after the fact.
 */
const GHSA_COVERED = new Set([
  'npm',
  'PyPI',
  'Maven',
  'Go',
  'NuGet',
  'RubyGems',
  'Packagist',
  'crates.io',
  'Pub',
  'Hex',
  'GitHub Actions',
]);

// OSV publishes a `[EMPTY]` bucket for NVD CVE stubs with no package data —
// 95%+ of rows are CVE IDs we already have in cve_details from CVElistV5.
// Skip to prevent duplicate/useless data.
const SKIP_ECOSYSTEMS = new Set(['[EMPTY]']);

interface SeverityEntry {
  type?: string;
  score?: string;
}

interface OsvAffectedEntry {
  package?: { name?: string; ecosystem?: string };
  versions?: string[];
  ranges?: unknown;
}

interface OsvRecord {
  id?: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: SeverityEntry[];
  affected?: OsvAffectedEntry[];
  published?: string;
  modified?: string;
}

/**
 * Parse an OSV severity[] array into a computed v3 score. The `cvss` package
 * supports only the `CVSS:3.0/` prefix — v3.0 and v3.1 use identical formulas
 * so we rewrite the prefix before scoring. v2 and v4 vectors fall through
 * with a null score (preserved verbatim in severity_raw).
 */
function parseCvss(sev: SeverityEntry[] | undefined): {
  vector: string | null;
  score: number | null;
  severity: string | null;
} {
  if (!Array.isArray(sev) || sev.length === 0) return { vector: null, score: null, severity: null };
  const v3 = sev.find((s) => s?.type === 'CVSS_V3');
  const entry = v3 ?? sev[0];
  if (!entry?.score) return { vector: null, score: null, severity: null };
  if (!v3) return { vector: entry.score, score: null, severity: null };
  try {
    const rewritten = entry.score.replace(/^CVSS:3\.1\//, 'CVSS:3.0/');
    const score = cvss.getScore(rewritten);
    if (typeof score !== 'number' || isNaN(score) || score === 0) {
      return { vector: entry.score, score: null, severity: null };
    }
    const rating = cvss.getRating(score);
    return {
      vector: entry.score,
      score: Number(score.toFixed(1)),
      severity: (rating ?? '').toUpperCase() || null,
    };
  } catch {
    return { vector: entry.score, score: null, severity: null };
  }
}

async function fetchEcosystems(): Promise<string[]> {
  const resp = await fetch(`${OSV_BASE}/ecosystems.txt`);
  if (!resp.ok) throw new Error(`ecosystems.txt HTTP ${resp.status}`);
  const text = await resp.text();
  return text.split('\n').map((l) => l.trim()).filter(Boolean);
}

async function loadGhsaSet(): Promise<Set<string>> {
  const result = await query<{ ghsa_id: string }>(`SELECT ghsa_id FROM ghsa_advisories`);
  return new Set(result.rows.map((r) => r.ghsa_id));
}

interface EcoSummary {
  scanned: number;
  upserted: number;
  skippedGhsa: number;
  skippedMalformed: number;
  errors: number;
}

async function syncEcosystem(
  ecosystem: string,
  ghsaSet: Set<string>,
  /** If set, skip any advisory whose `modified` is older than this cutoff. */
  modifiedSince: Date | null,
): Promise<EcoSummary & { skippedOld: number }> {
  const url = `${OSV_BASE}/${encodeURIComponent(ecosystem)}/all.zip`;
  const resp = await fetch(url, { signal: AbortSignal.timeout(30_000) });
  if (!resp.ok) {
    return { scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, skippedOld: 0, errors: 1 };
  }

  const buf = Buffer.from(await resp.arrayBuffer());
  const zip = await JSZip.loadAsync(buf);
  const files = Object.values(zip.files).filter((e) => e.name.endsWith('.json'));

  const summary = {
    scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, errors: 0, skippedOld: 0,
  };
  let advBatch: Array<{
    osv_id: string; ecosystem: string; aliases: string[];
    summary: string | null; details: string | null; severity_raw: unknown;
    cvss_vector: string | null; cvss_score: number | null; cvss_severity: string | null;
    published: string | null; modified: string | null;
  }> = [];
  let affBatch: Array<{
    osv_id: string; ecosystem: string; package_name: string;
    package_ecosystem: string; versions: string[] | null; ranges: unknown;
  }> = [];

  // De-dupe by (osv_id, ecosystem) within a batch — OSV zips occasionally
  // repeat an advisory across JSON files, and Postgres rejects ON CONFLICT
  // DO UPDATE with duplicates in one INSERT.
  const flushAdv = async () => {
    if (advBatch.length === 0) return;
    const byKey = new Map<string, (typeof advBatch)[number]>();
    for (const r of advBatch) byKey.set(`${r.osv_id}\0${r.ecosystem}`, r);
    const rows = [...byKey.values()];
    const values = rows
      .map(
        (_, i) =>
          `($${i * 11 + 1}, $${i * 11 + 2}, $${i * 11 + 3}, $${i * 11 + 4}, $${i * 11 + 5},` +
          ` $${i * 11 + 6}::jsonb, $${i * 11 + 7}, $${i * 11 + 8}::numeric,` +
          ` $${i * 11 + 9}, $${i * 11 + 10}, $${i * 11 + 11})`,
      )
      .join(', ');
    const params = rows.flatMap((r) => [
      r.osv_id, r.ecosystem, r.aliases, r.summary, r.details,
      JSON.stringify(r.severity_raw ?? []), r.cvss_vector, r.cvss_score, r.cvss_severity,
      r.published, r.modified,
    ]);
    await query(
      `INSERT INTO osv_advisories
         (osv_id, ecosystem, aliases, summary, details, severity_raw,
          cvss_vector, cvss_score, cvss_severity, published, modified)
       VALUES ${values}
       ON CONFLICT (osv_id, ecosystem) DO UPDATE SET
         aliases       = EXCLUDED.aliases,
         summary       = EXCLUDED.summary,
         details       = EXCLUDED.details,
         severity_raw  = EXCLUDED.severity_raw,
         cvss_vector   = EXCLUDED.cvss_vector,
         cvss_score    = EXCLUDED.cvss_score,
         cvss_severity = EXCLUDED.cvss_severity,
         published     = EXCLUDED.published,
         modified      = EXCLUDED.modified,
         updated_at    = NOW()`,
      params,
    );
    summary.upserted += rows.length;
    advBatch = [];
  };

  const flushAff = async () => {
    if (affBatch.length === 0) return;
    const byKey = new Map<string, (typeof affBatch)[number]>();
    for (const r of affBatch) {
      byKey.set(`${r.osv_id}\0${r.ecosystem}\0${r.package_ecosystem}\0${r.package_name}`, r);
    }
    const rows = [...byKey.values()];
    const values = rows
      .map(
        (_, i) =>
          `($${i * 6 + 1}, $${i * 6 + 2}, $${i * 6 + 3}, $${i * 6 + 4},` +
          ` $${i * 6 + 5}, $${i * 6 + 6}::jsonb)`,
      )
      .join(', ');
    const params = rows.flatMap((r) => [
      r.osv_id, r.ecosystem, r.package_name, r.package_ecosystem,
      r.versions, JSON.stringify(r.ranges ?? []),
    ]);
    await query(
      `INSERT INTO osv_affected
         (osv_id, ecosystem, package_name, package_ecosystem, versions, ranges)
       VALUES ${values}
       ON CONFLICT (osv_id, ecosystem, package_ecosystem, package_name) DO UPDATE SET
         versions = EXCLUDED.versions,
         ranges   = EXCLUDED.ranges`,
      params,
    );
    affBatch = [];
  };

  // Always flush advisories before affected rows — the composite FK in
  // `osv_affected` requires the parent to exist first.
  const flushBoth = async () => {
    await flushAdv();
    await flushAff();
  };

  for (const file of files) {
    summary.scanned++;
    let json: OsvRecord;
    try {
      json = JSON.parse(await file.async('string')) as OsvRecord;
    } catch {
      summary.skippedMalformed++;
      continue;
    }

    const osvId = json.id;
    if (!osvId || typeof osvId !== 'string') {
      summary.skippedMalformed++;
      continue;
    }

    // Delta mode: skip records older than the cutoff AND skip records with
    // no `modified` at all — in delta mode, a record with no timestamp can't
    // have changed by definition. Monthly full reconcile (modifiedSince=null)
    // still picks them up.
    if (modifiedSince) {
      if (!json.modified) {
        summary.skippedOld++;
        continue;
      }
      const m = new Date(json.modified);
      if (!isNaN(m.getTime()) && m < modifiedSince) {
        summary.skippedOld++;
        continue;
      }
    }

    const aliases = Array.isArray(json.aliases) ? json.aliases : [];
    if (aliases.some((a) => ghsaSet.has(a))) {
      summary.skippedGhsa++;
      continue;
    }

    const { vector, score, severity } = parseCvss(json.severity);

    advBatch.push({
      osv_id: osvId,
      ecosystem,
      aliases,
      summary: json.summary ?? null,
      details: json.details ?? null,
      severity_raw: json.severity ?? [],
      cvss_vector: vector,
      cvss_score: score,
      cvss_severity: severity,
      published: json.published ?? null,
      modified: json.modified ?? null,
    });

    if (Array.isArray(json.affected)) {
      for (const aff of json.affected) {
        const pkg = aff?.package;
        if (!pkg?.name || !pkg?.ecosystem) continue;
        affBatch.push({
          osv_id: osvId,
          ecosystem,
          package_name: pkg.name,
          package_ecosystem: pkg.ecosystem,
          versions: Array.isArray(aff.versions) ? aff.versions : null,
          ranges: aff.ranges ?? [],
        });
        if (affBatch.length >= BATCH_SIZE) await flushBoth();
      }
    }

    if (advBatch.length >= BATCH_SIZE) await flushBoth();
  }

  await flushBoth();

  return summary;
}

export async function GET(req: NextRequest) {
  const authError = verifyCronAuth(req);
  if (authError) return authError;

  // Mode select:
  //   - default (delta): records modified in the last DELTA_DAYS only
  //   - ?mode=full: full corpus (monthly reconcile). Guarded by
  //     isLastDayOfMonth() so the 28/29/30 slots in the `28-31 * *`
  //     schedule turn into no-ops in longer months.
  const mode = req.nextUrl.searchParams.get('mode') === 'full' ? 'full' : 'delta';
  if (mode === 'full' && !isLastDayOfMonth()) {
    return NextResponse.json({ ok: true, skipped: 'not last day of month' });
  }
  const modifiedSince = mode === 'delta'
    ? new Date(Date.now() - DELTA_DAYS * 24 * 60 * 60 * 1000)
    : null;

  // Stale cleanup — any 'running' row older than 15 min is a prior invocation
  // that Vercel killed before the terminal UPDATE ran.
  await query(
    `UPDATE feed_sync_log
     SET status = 'error', completed_at = NOW(),
         error_message = 'Timed out (auto-cleaned)'
     WHERE source = 'osv' AND status = 'running'
       AND started_at < NOW() - INTERVAL '15 minutes'`,
  );

  const logRes = await query<{ id: string }>(
    `INSERT INTO feed_sync_log (source, status, started_at)
     VALUES ('osv', 'running', NOW()) RETURNING id`,
  );
  const logId = logRes.rows[0].id;

  const totals = {
    scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, skippedOld: 0,
    errors: 0, ecosystemsProcessed: 0, ecosystemsTotal: 0,
  };
  const perEco: Record<string, EcoSummary & { skippedOld: number }> = {};

  const doWork = async (): Promise<NextResponse> => {
    const ghsaSet = await loadGhsaSet();

    const allEcos = await fetchEcosystems();
    const targets = allEcos.filter((e) => !GHSA_COVERED.has(e) && !SKIP_ECOSYSTEMS.has(e));
    totals.ecosystemsTotal = targets.length;

    for (const eco of targets) {
      try {
        const r = await syncEcosystem(eco, ghsaSet, modifiedSince);
        perEco[eco] = r;
        totals.scanned += r.scanned;
        totals.upserted += r.upserted;
        totals.skippedGhsa += r.skippedGhsa;
        totals.skippedMalformed += r.skippedMalformed;
        totals.skippedOld += r.skippedOld;
        totals.errors += r.errors;
        totals.ecosystemsProcessed++;
      } catch (err) {
        perEco[eco] = {
          scanned: 0, upserted: 0, skippedGhsa: 0, skippedMalformed: 0, skippedOld: 0, errors: 1,
        };
        totals.errors++;
        console.error(`[osv-cron] ${eco} failed:`, err instanceof Error ? err.message : err);
      }
    }

    await query(
      `UPDATE feed_sync_log
       SET status = 'success', completed_at = NOW(),
           records_inserted = $1, records_skipped = $2,
           metadata = $3
       WHERE id = $4 AND status = 'running'`,
      [
        totals.upserted,
        totals.skippedGhsa + totals.skippedMalformed,
        JSON.stringify({
          mode,
          modifiedSince: modifiedSince?.toISOString() ?? null,
          ghsaSetSize: ghsaSet.size,
          ecosystemsProcessed: totals.ecosystemsProcessed,
          ecosystemsTotal: totals.ecosystemsTotal,
          errors: totals.errors,
          skippedGhsa: totals.skippedGhsa,
          skippedMalformed: totals.skippedMalformed,
          skippedOld: totals.skippedOld,
          perEco,
        }),
        logId,
      ],
    );

    return NextResponse.json({
      ok: true,
      source: 'osv',
      mode,
      totals,
      perEco,
    });
  };

  try {
    return await withSoftTimeout(doWork, OSV_SOFT_TIMEOUT_MS);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error('[osv-cron] fatal:', err);
    await query(
      `UPDATE feed_sync_log
       SET status = 'error', completed_at = NOW(),
           error_message = $1, records_inserted = $2, records_skipped = $3
       WHERE id = $4 AND status = 'running'`,
      [msg.slice(0, 500), totals.upserted, totals.skippedGhsa + totals.skippedMalformed, logId],
    );
    return NextResponse.json({ ok: false, error: 'OSV sync failed' }, { status: 500 });
  }
}
