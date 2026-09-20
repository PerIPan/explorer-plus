import { USAGE_GUIDE } from './guide';
/**
 * Argument validation and tool execution for the shared tool catalogue.
 *
 * Shared by the A2A and MCP endpoints -- see ./declarations.ts for why there is
 * only one copy.
 *
 * Every tool reaches data the same way: validate/clamp the model-supplied
 * arguments, then call our own public /api/v1 over HTTP (callInternalApi). The
 * HTTP hop is intentional rather than a direct DB query -- it inherits the CDN
 * caching those routes set, so repeated agent calls are served at the edge and
 * never wake Neon.
 *
 * Nothing here imports from next/server or the db pool, which is what lets it
 * live in src/lib and be imported by any route.
 */

const BASE_URL = process.env.NEXT_PUBLIC_SITE_URL
  || (process.env.VERCEL_PROJECT_PRODUCTION_URL ? `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}` : null)
  || (process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : 'http://localhost:3000');


// -- Input validation --------------------------------------------------------

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const ATTACK_ID_RE = /^(AML\.)?(TA|T|G|S|M|C|CS|DS)\d{4}(\.\d{3})?$/;
// ICS assets use a bare A#### ID (A0001-A0018), which ATTACK_ID_RE above does
// NOT match -- its prefix group has no 'A' arm. Separate pattern, not a widened
// one: loosening ATTACK_ID_RE would let A0001 through on every technique tool.
const ASSET_ID_RE = /^A\d{4}$/;
const CAPEC_ID_RE = /^CAPEC-\d+$/;
// OSV IDs are highly heterogeneous — DSA-5678-1, USN-6543-1, LBSEC-2024-0001,
// ALAS-2024-0017, RLSA-2024-1234, SUSE-SU-2024:0123-1, KERN-*, etc. Accept
// anything that starts alnum and stays within a safe punctuation set.
const OSV_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._\-/~:]{1,127}$/;
const SECTOR_RE = /^[a-z][a-z0-9-]{1,28}[a-z0-9]$/;
const DOMAIN_RE = /^(enterprise|ics|mobile|atlas)-attack$/;
const SEVERITY_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const CAPEC_SEVERITY_VALUES = new Set(['Very Low', 'Low', 'Medium', 'High', 'Very High']);
const CAPEC_LIKELIHOOD_VALUES = new Set(['Low', 'Medium', 'High']);
const CAPEC_ABSTRACTION_VALUES = new Set(['Meta', 'Standard', 'Detailed']);
const ADVISORY_SOURCE_VALUES = new Set(['GHSA', 'OSV']);
// Ecosystem whitelist — union of GHSA (lowercase) + OSV (mixed case, preserved).
// Values here match what the /api/v1/advisories endpoint expects; it internally
// lowercases the GHSA side and case-matches the OSV side.
const ADVISORY_ECOSYSTEM_RE = /^[A-Za-z][A-Za-z0-9._\s-]{0,49}$/;

function validateCveId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return CVE_RE.test(s) ? s : null;
}

function validateAttackId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return ATTACK_ID_RE.test(s) ? s : null;
}

function validateCapecId(id: unknown): string | null {
  const s = String(id ?? '').trim().toUpperCase();
  return CAPEC_ID_RE.test(s) ? s : null;
}

function validateOsvId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return OSV_ID_RE.test(s) ? s : null;
}

function validateAdvisoryEcosystem(eco: unknown): string | null {
  const s = String(eco ?? '').trim();
  return ADVISORY_ECOSYSTEM_RE.test(s) ? s : null;
}

function validateAssetId(id: unknown): string | null {
  const s = String(id ?? '').trim().toUpperCase();
  return ASSET_ID_RE.test(s) ? s : null;
}

function validateSector(slug: unknown): string | null {
  const s = String(slug ?? '').trim().toLowerCase();
  return SECTOR_RE.test(s) ? s : null;
}

function validateDomain(d: unknown): string | null {
  const s = String(d ?? '').trim();
  return DOMAIN_RE.test(s) ? s : null;
}

function sanitizeSearch(q: unknown): string {
  return String(q ?? '').trim().slice(0, 200);
}

// -- Input validation allowlists ----------------------------------------------

const IOC_TYPES = new Set(['ip', 'domain', 'url', 'hash', 'cve', 'email']);
const IOC_SOURCES = new Set(['otx', 'threatfox', 'malwarebazaar', 'cisa_kev']);
const SIGMA_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'informational']);
const PLATFORMS = new Set(['windows', 'linux', 'macos']);
const PURDUE_LEVELS = new Set(['l0', 'l1', 'l2', 'l3', 'l3_5', 'l4', 'l5']);
const PURDUE_ZONES = new Set(['ot', 'dmz', 'it']);

/**
 * Guard for optional filters that are validated then applied.
 *
 * A filter the caller supplied but we could not use must NOT be silently
 * dropped: the query still runs, returns unfiltered rows, and the model
 * reports them as though the filter applied -- e.g. sector:'Financial
 * Services' (not a slug) yields the top groups overall, described back to the
 * user as "these groups target the financial sector". Failing loudly costs one
 * retry; failing silently produces a confident falsehood.
 */
function badFilter(name: string, value: unknown, hint: string): Record<string, string> {
  return { error: `Invalid ${name}: ${JSON.stringify(String(value)).slice(0, 60)}. ${hint}` };
}

/**
 * Page number for the paginated list endpoints.
 *
 * Without this a model can see `pagination.total: 340` next to 50 rows and has
 * no way to reach row 51 -- observed behaviour is either reporting the page as
 * the whole answer, or re-issuing the same call with a bigger limit (silently
 * clamped, identical rows back) until it gives up.
 */
function clampPage(val: unknown): string {
  return String(Math.min(Math.max(Math.trunc(Number(val) || 1), 1), 1000));
}

function clampLimit(val: unknown, def: number, max: number): string {
  return String(Math.min(Math.max(Number(val) || def, 1), max));
}

// -- Internal API caller ------------------------------------------------------

async function callInternalApi(path: string): Promise<Record<string, unknown>> {
  const url = `${BASE_URL}/api/v1${path}`;
  const resp = await fetch(url, {
    headers: { 'Accept': 'application/json' },
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) {
    // Surface the API's own message. Routes return { error, code } via
    // errorResponse(), and "Asset A0099 not found" tells a model what to do
    // next, whereas a bare "API returned 404" reads as "the service is broken"
    // and tends to end with the model declaring the entity absent entirely.
    let detail: string | undefined;
    try {
      const body = (await resp.json()) as { error?: unknown };
      if (typeof body?.error === 'string') detail = body.error;
    } catch {
      // Non-JSON error body — fall through to the status-only message.
    }
    return { error: detail ?? `API returned ${resp.status}`, status: resp.status, path };
  }
  return resp.json() as Promise<Record<string, unknown>>;
}

export async function executeTool(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  switch (name) {
    case 'search_cves': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (isNaN(d.getTime())) return badFilter('since', args.since, 'Pass a full ISO-8601 date such as 2026-09-01 or 2026-09-01T00:00:00Z, computed from the current date.');
        params.set('since', d.toISOString());
      }
      if (args.app) params.set('app', sanitizeSearch(args.app));
      if (args.version) params.set('version', sanitizeSearch(args.version).slice(0, 100));
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/cves?${params}`);
    }
    case 'get_cve_detail': {
      const id = validateCveId(args.cve_id);
      if (!id) return { error: 'Invalid CVE ID format' };
      const qp = args.version ? `?version=${encodeURIComponent(sanitizeSearch(args.version).slice(0, 100))}` : '';
      return callInternalApi(`/cves/${id}${qp}`);
    }
    case 'get_technique_intelligence': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/feed/intelligence/${id}`);
    }
    case 'get_technique_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/techniques/${id}`);
    }
    case 'get_group_profile': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid group ID format' };
      return callInternalApi(`/groups/${id}`);
    }
    case 'search_groups': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      if (args.sector !== undefined && args.sector !== null && args.sector !== '') {
        const sec = validateSector(args.sector);
        if (!sec) return badFilter('sector', args.sector, 'Use a lowercase sector slug such as financial, healthcare, government, energy. Call get_sector_threats or omit the filter if unsure.');
        params.set('sector', sec);
      }
      const dom = validateDomain(args.domain);
      if (dom) params.set('domain', dom);
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/groups?${params}`);
    }
    case 'get_application_security': {
      const v = String(args.vendor ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      const p = String(args.product ?? '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
      if (!v || !p) return { error: 'Vendor and product are required' };
      const qp = args.version ? `?version=${encodeURIComponent(sanitizeSearch(args.version).slice(0, 100))}` : '';
      return callInternalApi(`/applications/${v}/${p}${qp}`);
    }
    case 'search_applications': {
      const params = new URLSearchParams();
      if (args.search) params.set('search', sanitizeSearch(args.search));
      if (args.version) params.set('version', sanitizeSearch(args.version).slice(0, 100));
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/applications?${params}`);
    }
    case 'get_sector_threats': {
      const sec = validateSector(args.sector);
      if (!sec) return { error: 'Invalid sector slug' };
      return callInternalApi(`/sectors/${sec}/relationships`);
    }
    case 'search_entities': {
      const s = sanitizeSearch(args.q);
      if (s.length < 3) return { error: 'Search query must be at least 3 characters' };
      return callInternalApi(`/search?q=${encodeURIComponent(s)}`);
    }
    case 'get_dashboard_stats': {
      const params = new URLSearchParams();
      const dom = validateDomain(args.domain);
      if (dom) params.set('domain', dom);
      if (args.sector !== undefined && args.sector !== null && args.sector !== '') {
        const sec = validateSector(args.sector);
        if (!sec) return badFilter('sector', args.sector, 'Use a lowercase sector slug such as financial, healthcare, government, energy. Call get_sector_threats or omit the filter if unsure.');
        params.set('sector', sec);
      }
      return callInternalApi(`/dashboard?${params}`);
    }
    case 'get_framework_mappings': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/frameworks/technique/${id}`);
    }
    case 'get_threat_reports': {
      const params = new URLSearchParams();
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/feed/reports?${params}`);
    }
    // -- New tools ------------------------------------------------------------
    case 'get_software_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid software ID format' };
      return callInternalApi(`/software/${id}`);
    }
    case 'search_software': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      if (args.sector !== undefined && args.sector !== null && args.sector !== '') {
        const sec = validateSector(args.sector);
        if (!sec) return badFilter('sector', args.sector, 'Use a lowercase sector slug such as financial, healthcare, government, energy. Call get_sector_threats or omit the filter if unsure.');
        params.set('sector', sec);
      }
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/software?${params}`);
    }
    case 'get_campaign_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid campaign ID format' };
      return callInternalApi(`/campaigns/${id}`);
    }
    case 'search_campaigns': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      if (args.sector !== undefined && args.sector !== null && args.sector !== '') {
        const sec = validateSector(args.sector);
        if (!sec) return badFilter('sector', args.sector, 'Use a lowercase sector slug such as financial, healthcare, government, energy. Call get_sector_threats or omit the filter if unsure.');
        params.set('sector', sec);
      }
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/campaigns?${params}`);
    }
    case 'get_mitigation_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid mitigation ID format' };
      return callInternalApi(`/mitigations/${id}`);
    }
    case 'search_mitigations': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 3) return { error: 'Search query must be at least 3 characters' };
      const params = new URLSearchParams();
      if (s.length >= 3) params.set('search', s);
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/mitigations?${params}`);
    }
    case 'search_iocs': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.type) {
        const t = String(args.type).toLowerCase();
        if (IOC_TYPES.has(t)) params.set('type', t);
      }
      if (args.source) {
        const s = String(args.source).toLowerCase();
        if (IOC_SOURCES.has(s)) params.set('source', s);
      }
      if (args.malware) params.set('malware', sanitizeSearch(args.malware));
      if (args.since) {
        const d = new Date(String(args.since));
        if (isNaN(d.getTime())) return badFilter('since', args.since, 'Pass a full ISO-8601 date such as 2026-09-01 or 2026-09-01T00:00:00Z, computed from the current date.');
        params.set('since', d.toISOString());
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/iocs?${params}`);
    }
    case 'search_sigma_rules': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (!tid) return badFilter('technique', args.technique, 'Use a full ATT&CK ID such as T1059 or T1059.001, not a bare number.');
        params.set('technique', tid);
      }
      if (args.level) {
        const lvl = String(args.level).toLowerCase();
        if (SIGMA_LEVELS.has(lvl)) params.set('level', lvl);
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/sigma?${params}`);
    }
    case 'search_atomic_tests': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (!tid) return badFilter('technique', args.technique, 'Use a full ATT&CK ID such as T1059 or T1059.001, not a bare number.');
        params.set('technique', tid);
      }
      if (args.platform) {
        const plat = String(args.platform).toLowerCase();
        if (PLATFORMS.has(plat)) params.set('platform', plat);
      }
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/feed/atomic?${params}`);
    }
    case 'get_external_actor': {
      const n = sanitizeSearch(args.name);
      if (n.length < 2) return { error: 'Actor name must be at least 2 characters' };
      return callInternalApi(`/external-actors/${encodeURIComponent(n)}`);
    }
    case 'search_external_actors': {
      const s = sanitizeSearch(args.search);
      if (s.length > 0 && s.length < 2) return { error: 'Search query must be at least 2 characters' };
      const params = new URLSearchParams();
      if (s.length >= 2) params.set('search', s);
      if (args.country) params.set('country', sanitizeSearch(args.country));
      if (args.category) params.set('category', sanitizeSearch(args.category));
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/external-actors?${params}`);
    }
    case 'get_tactic_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid tactic ID format' };
      return callInternalApi(`/tactics/${id}`);
    }
    case 'get_data_source_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid data source ID format' };
      return callInternalApi(`/data-sources/${id}`);
    }
    case 'get_owasp_top10': {
      // An unrecognised framework was passed straight through and the endpoint
      // ignored it, returning all 30 rows with a 200 -- verified against prod.
      // Same silent-drop class as the sector/since filters: the model asks for
      // one framework, gets three, and reports them as that one.
      const OWASP_FRAMEWORKS = new Set(['web-2021', 'ml-2023', 'llm-2025']);
      let qs = '';
      if (args.framework !== undefined && args.framework !== null && args.framework !== '') {
        const fw = String(args.framework).toLowerCase();
        if (!OWASP_FRAMEWORKS.has(fw)) {
          return badFilter('framework', args.framework, 'Use web-2021, ml-2023 or llm-2025, or omit it to get all three.');
        }
        qs = `?framework=${encodeURIComponent(fw)}`;
      }
      return callInternalApi(`/frameworks/owasp${qs}`);
    }
    case 'get_owasp_category': {
      const cat = String(args.category_id ?? '').toUpperCase();
      if (!/^(A|ML|LLM)\d{2}$/.test(cat)) return { error: 'Invalid category ID (A01-A10, ML01-ML10, LLM01-LLM10)' };
      return callInternalApi(`/frameworks/owasp/${cat}`);
    }
    case 'get_ghsa_detail': {
      // Preserve case of the random segments — GHSA stores them lowercase.
      const id = String(args.ghsa_id ?? '').replace(/^ghsa-/i, 'GHSA-');
      if (!/^GHSA(-[0-9a-z]{4}){3}$/.test(id)) return { error: 'Invalid GHSA ID format' };
      const qp = args.version ? `?version=${encodeURIComponent(sanitizeSearch(args.version).slice(0, 100))}` : '';
      return callInternalApi(`/ghsa/${id}${qp}`);
    }
    case 'get_package_vulnerabilities': {
      const eco = String(args.ecosystem ?? '').toLowerCase();
      const name = String(args.package_name ?? '');
      if (!/^[a-z][a-z0-9-]{1,49}$/.test(eco)) return { error: 'Invalid ecosystem' };
      if (!name || name.length > 500) return { error: 'Invalid package name' };
      const qp = args.version ? `?version=${encodeURIComponent(sanitizeSearch(args.version).slice(0, 100))}` : '';
      return callInternalApi(`/packages/${eco}/${encodeURIComponent(name)}${qp}`);
    }
    case 'search_ghsa': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.ecosystem) {
        const eco = String(args.ecosystem).toLowerCase();
        if (/^[a-z][a-z0-9-]{1,49}$/.test(eco)) params.set('ecosystem', eco);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (isNaN(d.getTime())) return badFilter('since', args.since, 'Pass a full ISO-8601 date such as 2026-09-01 or 2026-09-01T00:00:00Z, computed from the current date.');
        params.set('since', d.toISOString());
      }
      if (args.has_cve !== undefined && args.has_cve !== null && args.has_cve !== '') {
        const hc = String(args.has_cve).toLowerCase();
        if (hc !== 'true' && hc !== 'false') return badFilter('has_cve', args.has_cve, 'Use true or false.');
        params.set('has_cve', hc);
      }
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 10, 50));
      return callInternalApi(`/ghsa?${params}`);
    }
    case 'get_cve_packages':
    case 'cve_to_packages': { // legacy alias — external agents may have cached the old name
      const id = validateCveId(args.cve_id);
      if (!id) return { error: 'Invalid CVE ID format' };
      return callInternalApi(`/cves/${id}/packages`);
    }
    case 'get_capec_detail': {
      const id = validateCapecId(args.capec_id);
      if (!id) return { error: 'Invalid CAPEC ID format (expected CAPEC-N)' };
      return callInternalApi(`/capec/${id}`);
    }
    case 'search_capec': {
      const params = new URLSearchParams();
      const q = sanitizeSearch(args.q);
      if (q.length > 0 && q.length < 2) return { error: 'Search query must be at least 2 characters' };
      if (q.length >= 2) params.set('q', q);
      if (args.abstraction) {
        const a = String(args.abstraction);
        if (CAPEC_ABSTRACTION_VALUES.has(a)) params.set('abstraction', a);
      }
      if (args.severity) {
        const s = String(args.severity);
        if (CAPEC_SEVERITY_VALUES.has(s)) params.set('severity', s);
      }
      if (args.likelihood) {
        const l = String(args.likelihood);
        if (CAPEC_LIKELIHOOD_VALUES.has(l)) params.set('likelihood', l);
      }
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 20, 50));
      return callInternalApi(`/capec?${params}`);
    }
    case 'search_advisories': {
      const params = new URLSearchParams();
      const q = sanitizeSearch(args.q);
      if (q.length > 0 && q.length < 3) return { error: 'Search query must be at least 3 characters' };
      if (q.length >= 3) params.set('q', q);
      if (args.source) {
        const s = String(args.source).toUpperCase();
        if (ADVISORY_SOURCE_VALUES.has(s)) params.set('source', s);
      }
      if (args.severity) {
        const sev = String(args.severity).toUpperCase();
        if (SEVERITY_VALUES.has(sev)) params.set('severity', sev);
      }
      if (args.ecosystem) {
        const eco = validateAdvisoryEcosystem(args.ecosystem);
        if (eco) params.set('ecosystem', eco);
      }
      if (args.since) {
        const d = new Date(String(args.since));
        if (isNaN(d.getTime())) return badFilter('since', args.since, 'Pass a full ISO-8601 date such as 2026-09-01 or 2026-09-01T00:00:00Z, computed from the current date.');
        params.set('since', d.toISOString());
      }
      if (args.has_cve !== undefined && args.has_cve !== null && args.has_cve !== '') {
        const hc = String(args.has_cve).toLowerCase();
        if (hc !== 'true' && hc !== 'false') return badFilter('has_cve', args.has_cve, 'Use true or false.');
        params.set('has_cve', hc);
      }
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 50, 100));
      return callInternalApi(`/advisories?${params}`);
    }
    case 'get_osv_detail': {
      const id = validateOsvId(args.osv_id);
      if (!id) return { error: 'Invalid OSV ID format' };
      return callInternalApi(`/osv/${encodeURIComponent(id)}`);
    }
    case 'list_compliance_frameworks': {
      const params = new URLSearchParams();
      if (args.include_all === true || args.include_all === 'true') params.set('include_all', '1');
      return callInternalApi(`/compliance/frameworks?${params}`);
    }
    case 'get_compliance_framework': {
      const key = String(args.framework_key ?? '').trim().toLowerCase();
      if (!/^[a-z0-9][a-z0-9-]{1,80}$/.test(key)) return { error: 'Invalid framework_key format' };
      return callInternalApi(`/compliance/frameworks/${encodeURIComponent(key)}`);
    }
    case 'get_technique_compliance': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      const params = new URLSearchParams();
      if (args.include_all === true || args.include_all === 'true') params.set('include_all', '1');
      return callInternalApi(`/compliance/techniques/${encodeURIComponent(id)}?${params}`);
    }
    case 'search_assets': {
      const params = new URLSearchParams();
      // /api/v1/assets rejects search terms under 2 chars (zod .min(2)), so a
      // 1-char term is dropped rather than sent and 400'd.
      const q = sanitizeSearch(args.search);
      if (q.length >= 2) params.set('search', q);
      const level = String(args.level ?? '').toLowerCase();
      if (PURDUE_LEVELS.has(level)) params.set('level', level);
      const zone = String(args.zone ?? '').toLowerCase();
      if (PURDUE_ZONES.has(zone)) params.set('zone', zone);
      if (args.sector !== undefined && args.sector !== null && args.sector !== '') {
        const sector = validateSector(args.sector);
        if (!sector) return badFilter('sector', args.sector, 'Use a lowercase sector slug such as financial, healthcare, government, energy. Call get_sector_threats or omit the filter if unsure.');
        params.set('sector', sector);
      }
      if (typeof args.boundary === 'boolean') params.set('boundary', String(args.boundary));
      if (args.page !== undefined) params.set('page', clampPage(args.page));
      params.set('limit', clampLimit(args.limit, 50, 200));
      return callInternalApi(`/assets?${params}`);
    }
    case 'get_asset_detail': {
      const id = validateAssetId(args.asset_id);
      if (!id) return { error: 'Invalid asset ID format -- expected A0001 through A0018' };
      return callInternalApi(`/assets/${id}`);
    }
    case 'get_purdue_model':
      return callInternalApi('/frameworks/purdue');
    // Served from memory: no HTTP hop, no DB, no Neon wake.
    case 'get_usage_guide':
      return { guide: USAGE_GUIDE };
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

