// scripts/lib/nvd-feed.mjs
//
// Reader for the community reconstruction of NVD's legacy JSON data feeds
// (github.com/fkie-cad/nvd-json-data-feeds). NVD retired its own JSON feeds in
// December 2023 and left only the rate-limited 2.0 API; this republishes the
// API's data as one file per year, several times a day, in the same NVD 2.0
// schema.
//
// Why this and not services.nvd.nist.gov:
//   * One ~2-5MB download covers a whole year WITH every record's
//     `configurations`. The API's per-CVE form (`?cveId=`) needs one request
//     per record at 800ms, which is what let a 162,263-CVE product backlog
//     build up with no way to drain it.
//   * No 50 req/30s rate limit.
//   * Cloudflare sits in front of the API and currently answers Node's fetch
//     with 404 while serving the identical URL to curl — a client fingerprint
//     issue no header fixes. GitHub releases have no such problem.
//
// Shared by scripts/sync-cve-products.mjs and scripts/audit-cve-coverage.mjs.

import fs from 'fs';
import os from 'os';
import path from 'path';
import { execFileSync } from 'child_process';

export const NVD_FEED_BASE =
  'https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download';

/**
 * Decompress .xz. Node ships zlib, which does gzip/deflate/brotli and NOT xz,
 * and adding a native xz binding for one call is not worth the install
 * surface. `xz` is present on ubuntu-latest runners; python3's lzma is present
 * basically everywhere including macOS, where `xz` often is not. Try both
 * before giving up, and say which are missing rather than failing opaquely.
 */
function decompressXz(xzPath, outPath) {
  try {
    execFileSync('xz', ['-dc', xzPath], { stdio: ['ignore', fs.openSync(outPath, 'w'), 'inherit'] });
    return;
  } catch { /* fall through to python */ }
  try {
    execFileSync('python3', [
      '-c',
      'import lzma,sys,shutil\nwith lzma.open(sys.argv[1]) as f, open(sys.argv[2],"wb") as o: shutil.copyfileobj(f,o)',
      xzPath, outPath,
    ], { stdio: 'inherit' });
    return;
  } catch { /* fall through to the throw */ }
  throw new Error(
    'cannot decompress .xz: neither `xz` nor `python3` (with lzma) is available. ' +
    'Install xz-utils, or run where python3 exists.',
  );
}

/**
 * Download one year's feed and return its parsed records.
 *
 * Streams to a temp file and decompresses to a temp file rather than buffering:
 * a decompressed year is ~80MB of JSON (CVE-2016's own .meta reports
 * size:78769816 against xzSize:2485560), and capturing that through a pipe
 * would hit execFileSync's 1MiB default maxBuffer.
 *
 * @param {string} year four-digit year, e.g. '2016'
 * @returns {Promise<{items: any[], cveCount: number, timestamp: string}>}
 */
export async function fetchYearFeed(year) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), `nvd-${year}-`));
  const xzPath = path.join(tmpDir, `CVE-${year}.json.xz`);
  const jsonPath = path.join(tmpDir, `CVE-${year}.json`);
  try {
    const res = await fetch(`${NVD_FEED_BASE}/CVE-${year}.json.xz`, {
      redirect: 'follow',
      signal: AbortSignal.timeout(180_000),
    });
    if (!res.ok) throw new Error(`feed ${year}: HTTP ${res.status}`);
    fs.writeFileSync(xzPath, Buffer.from(await res.arrayBuffer()));
    decompressXz(xzPath, jsonPath);
    const parsed = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
    return {
      items: parsed.cve_items ?? [],
      // The feed states its own count; trust it for reporting but never in
      // place of counting what was actually parsed.
      cveCount: parsed.cve_count ?? (parsed.cve_items?.length ?? 0),
      timestamp: parsed.timestamp ?? null,
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

/**
 * The years the feed publishes, oldest first. Derived from the release's asset
 * list so a new year appears without a code change.
 */
export async function availableYears() {
  const res = await fetch(
    'https://api.github.com/repos/fkie-cad/nvd-json-data-feeds/releases/latest',
    { headers: { Accept: 'application/vnd.github+json' }, signal: AbortSignal.timeout(60_000) },
  );
  if (!res.ok) throw new Error(`release listing: HTTP ${res.status}`);
  const json = await res.json();
  return (json.assets ?? [])
    .map((a) => /^CVE-(\d{4})\.json\.xz$/.exec(a.name)?.[1])
    .filter(Boolean)
    .sort();
}
