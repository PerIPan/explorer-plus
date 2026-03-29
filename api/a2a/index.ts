import type { VercelRequest, VercelResponse } from '@vercel/node';
import { GoogleGenAI } from '@google/genai';
import { query } from '../v1/lib/db.js';

/**
 * A2A (Agent-to-Agent) endpoint — JSON-RPC 2.0 over HTTPS.
 * Accepts natural language queries, uses Gemini 2.5 Flash-Lite to interpret,
 * calls internal APIs, returns structured results.
 *
 * Rate limit: 50 req/day per IP, no auth required.
 */

// Vercel body size limit
export const config = { api: { bodyParser: { sizeLimit: '16kb' } } };

const DAILY_LIMIT = 50;
const MODEL = 'gemini-3.1-flash-lite-preview';
const MAX_INPUT_LENGTH = 2000;
const BASE_URL = 'https://mitre-explorer.org';

// ── Input validation ─────────────────────────────────────────────────────────

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const ATTACK_ID_RE = /^(AML\.)?(TA|T|G|S|M|C|CS|DS)\d{4}(\.\d{3})?$/;
const SECTOR_RE = /^[a-z][a-z0-9-]{1,28}[a-z0-9]$/;
const DOMAIN_RE = /^(enterprise|ics|mobile|atlas)-attack$/;
const SEVERITY_VALUES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);

function validateCveId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return CVE_RE.test(s) ? s : null;
}

function validateAttackId(id: unknown): string | null {
  const s = String(id ?? '').trim();
  return ATTACK_ID_RE.test(s) ? s : null;
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

// ── Gemini function declarations for our API ─────────────────────────────────

const TOOL_DECLARATIONS = [
  {
    name: 'search_cves',
    description: 'Search CVE vulnerabilities by keyword, severity, or date range. Returns CVE ID, CVSS score, severity, description, and linked techniques.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (CVE ID, keyword, CWE)' },
        severity: { type: "STRING", description: 'Filter by severity: CRITICAL, HIGH, MEDIUM, LOW' },
        since: { type: "STRING", description: 'ISO date string — only CVEs published after this date' },
        limit: { type: "NUMBER", description: 'Max results (default 10, max 50)' },
      },
    },
  },
  {
    name: 'get_cve_detail',
    description: 'Get full details for a specific CVE including all CWEs, CVSS breakdown, affected applications, linked techniques (via CAPEC + CTID), and CISA KEV status.',
    parameters: {
      type: "OBJECT",
      properties: {
        cve_id: { type: "STRING", description: 'CVE identifier, e.g. CVE-2024-3400' },
      },
      required: ['cve_id'],
    },
  },
  {
    name: 'get_technique_intelligence',
    description: 'Get intelligence for an ATT&CK or ATLAS technique: threat groups, Sigma rules, Atomic tests, D3FEND countermeasures, affected applications, detection strategies.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK ID (e.g. T1059, T1190) or ATLAS ID (e.g. AML.T0051)' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_technique_detail',
    description: 'Get detailed technique information: description, tactics, platforms, sub-techniques, procedures, mitigations, data sources, ATLAS cross-references.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK or ATLAS technique ID' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_group_profile',
    description: 'Get threat group profile: techniques used, software, campaigns, targeted sectors, targeted applications.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Group ATT&CK ID, e.g. G0016 for APT29' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_groups',
    description: 'Search threat groups by name or description (min 3 characters). Returns group ID, name, and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug (e.g. financial, healthcare, government)' },
        domain: { type: "STRING", description: 'ATT&CK domain: enterprise-attack, ics-attack, mobile-attack, atlas-attack' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_application_security',
    description: 'Get security posture for a vendor/product: CVEs, CWE weakness profile, reachable techniques, associated threat groups.',
    parameters: {
      type: "OBJECT",
      properties: {
        vendor: { type: "STRING", description: 'Vendor name, e.g. microsoft, apache, litellm' },
        product: { type: "STRING", description: 'Product name, e.g. windows_server_2022, http_server, litellm' },
      },
      required: ['vendor', 'product'],
    },
  },
  {
    name: 'search_applications',
    description: 'Search applications by name. Returns vendor, product, CVE count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_sector_threats',
    description: 'Get threat landscape for an industry sector: groups, techniques, campaigns, vulnerable applications.',
    parameters: {
      type: "OBJECT",
      properties: {
        sector: { type: "STRING", description: 'Sector slug: financial, healthcare, government, energy, telecom, defense, technology, education, media, retail, transportation, manufacturing' },
      },
      required: ['sector'],
    },
  },
  {
    name: 'search_entities',
    description: 'Cross-domain search across all entity types: techniques, groups, software, campaigns, mitigations, data sources, applications. Minimum 3 characters.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (minimum 3 characters)' },
      },
      required: ['q'],
    },
  },
  {
    name: 'get_dashboard_stats',
    description: 'Get knowledge base overview: entity counts, top groups, most targeted techniques, sector breakdown.',
    parameters: {
      type: "OBJECT",
      properties: {
        domain: { type: "STRING", description: 'Optional domain filter' },
        sector: { type: "STRING", description: 'Optional sector filter' },
      },
    },
  },
  {
    name: 'get_framework_mappings',
    description: 'Get compliance/framework mappings for a technique: NIST 800-53 controls, MITRE Engage activities, VERIS mappings, cloud controls (Azure/GCP).',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'ATT&CK technique ID' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_threat_reports',
    description: 'Get recent threat intelligence reports from AlienVault OTX, DFIR Report, Unit42, Microsoft Security, Talos. Reports are mapped to ATT&CK techniques.',
    parameters: {
      type: "OBJECT",
      properties: {
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  // ── New tools ─────────────────────────────────────────────────────────────
  {
    name: 'get_software_detail',
    description: 'Get malware or tool profile: techniques it uses, groups that use it, campaigns, platforms. Covers 914 ATT&CK software entries.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Software ATT&CK ID, e.g. S0154 for Cobalt Strike' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_software',
    description: 'Search malware and tools by name. Returns software ID, name, type (malware/tool), and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_campaign_detail',
    description: 'Get campaign details: techniques used, software deployed, groups involved, timeline.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Campaign ATT&CK ID, e.g. C0028' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_campaigns',
    description: 'Search named campaigns. Returns campaign ID, name, dates, and linked groups.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        sector: { type: "STRING", description: 'Filter by sector slug' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'get_mitigation_detail',
    description: 'Get mitigation details: description, techniques it addresses, domain coverage.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Mitigation ATT&CK ID, e.g. M1036' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'search_mitigations',
    description: 'Search mitigations by name or description. Returns mitigation ID, name, and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 3 characters)' },
        limit: { type: "NUMBER", description: 'Max results (default 10)' },
      },
    },
  },
  {
    name: 'search_iocs',
    description: 'Search Indicators of Compromise: IPs, domains, hashes, URLs, CVEs. Includes VirusTotal verdicts and malware families. Sources: OTX, ThreatFox, MalwareBazaar, CISA KEV.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query (IOC value, keyword)' },
        type: { type: "STRING", description: 'IOC type: ip, domain, url, hash, cve, email' },
        source: { type: "STRING", description: 'Source filter: otx, threatfox, malwarebazaar, cisa_kev' },
        malware: { type: "STRING", description: 'Filter by malware family name' },
        since: { type: "STRING", description: 'ISO date — only IOCs seen after this date' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'search_sigma_rules',
    description: 'Search Sigma detection rules by keyword, technique, or severity level. 3,100+ rules from SigmaHQ.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword in title/description' },
        technique: { type: "STRING", description: 'Filter by ATT&CK technique ID, e.g. T1059' },
        level: { type: "STRING", description: 'Severity level: critical, high, medium, low, informational' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'search_atomic_tests',
    description: 'Search Atomic Red Team tests by keyword, technique, or platform. 1,770+ tests for adversary emulation.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search keyword' },
        technique: { type: "STRING", description: 'Filter by ATT&CK technique ID' },
        platform: { type: "STRING", description: 'Platform filter: windows, linux, macos' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'get_external_actor',
    description: 'Get external threat actor profile from ETDA/ThaiCERT: country, motivation, state sponsor, suspected victims, MITRE group mapping.',
    parameters: {
      type: "OBJECT",
      properties: {
        name: { type: "STRING", description: 'Actor name, e.g. APT28, Lazarus Group' },
      },
      required: ['name'],
    },
  },
  {
    name: 'search_external_actors',
    description: 'Search 514 external threat actors by name, country, or category. Includes state sponsors, motivation, and MITRE ATT&CK group mappings.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword (minimum 2 characters)' },
        country: { type: "STRING", description: 'Country filter, e.g. Russia, China, Iran' },
        category: { type: "STRING", description: 'Category filter' },
        limit: { type: "NUMBER", description: 'Max results (default 20)' },
      },
    },
  },
  {
    name: 'get_tactic_detail',
    description: 'Get tactic details: description, all techniques under this tactic, domain.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Tactic ATT&CK ID, e.g. TA0001 for Initial Access' },
      },
      required: ['attack_id'],
    },
  },
  {
    name: 'get_data_source_detail',
    description: 'Get data source details: description, data components, techniques it can detect.',
    parameters: {
      type: "OBJECT",
      properties: {
        attack_id: { type: "STRING", description: 'Data source ATT&CK ID, e.g. DS0009 for Process' },
      },
      required: ['attack_id'],
    },
  },
];

const SYSTEM_INSTRUCTION = `You are the MITRE Explorer threat intelligence agent. You help security professionals, SOC analysts, and AI agents query the MITRE ATT&CK knowledge base, CVE vulnerabilities, and application security data.

Use the available tools to answer questions. Always call a tool before answering — never guess or hallucinate data. If the user asks about a CVE, technique, group, or application, look it up.

When responding:
- Be concise and factual
- For EVERY CVE mentioned, always include: CVE ID, CVSS score, severity (CRITICAL/HIGH/MEDIUM/LOW), published date, and linked ATT&CK techniques if available
- Include clickable markdown links to MITRE Explorer for every entity mentioned:
  - CVEs: [CVE-2024-3400](https://mitre-explorer.org/cti/cves/CVE-2024-3400)
  - Techniques: [T1059](https://mitre-explorer.org/techniques/T1059)
  - Groups: [APT29](https://mitre-explorer.org/?entity=G0016&tab=actor)
  - Applications: [LiteLLM](https://mitre-explorer.org/?entity=litellm%2Flitellm&tab=application-map)
- Use tables for structured data when listing multiple items
- Always mention total result count (e.g. "Showing 10 of 47 results")
- Keep a consistent schema per entity type — do not change column layout between responses
- Do not truncate CVE descriptions mid-sentence — include the full description or summarize it cleanly
- When reporting CVEs, add this note at the end: "NVD typically adds CPE entries days after CVE publication — recent CVEs may show empty until enriched."
- For each CVE with linked techniques, list the technique IDs (e.g. T1190, T1059) — these are the bridge between a vulnerability and the actual attack behaviour it enables`;

// ── Internal API caller ──────────────────────────────────────────────────────

async function callInternalApi(path: string): Promise<Record<string, unknown>> {
  const url = `${BASE_URL}/api/v1${path}`;
  const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
  if (!resp.ok) return { error: `API returned ${resp.status}`, path };
  return resp.json() as Promise<Record<string, unknown>>;
}

async function executeTool(name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
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
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/cves?${params}`);
    }
    case 'get_cve_detail': {
      const id = validateCveId(args.cve_id);
      if (!id) return { error: 'Invalid CVE ID format' };
      return callInternalApi(`/cves/${id}`);
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
      const params = new URLSearchParams();
      const s = sanitizeSearch(args.search);
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      const dom = validateDomain(args.domain);
      if (dom) params.set('domain', dom);
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/groups?${params}`);
    }
    case 'get_application_security': {
      const v = String(args.vendor ?? '').toLowerCase().replace(/[^a-z0-9_]/g, '');
      const p = String(args.product ?? '').toLowerCase().replace(/[^a-z0-9_]/g, '');
      if (!v || !p) return { error: 'Vendor and product are required' };
      return callInternalApi(`/applications/${v}/${p}`);
    }
    case 'search_applications': {
      const params = new URLSearchParams();
      if (args.search) params.set('search', sanitizeSearch(args.search));
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
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
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      return callInternalApi(`/dashboard?${params}`);
    }
    case 'get_framework_mappings': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid ATT&CK ID format' };
      return callInternalApi(`/frameworks/technique/${id}`);
    }
    case 'get_threat_reports': {
      const params = new URLSearchParams();
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/feed/reports?${params}`);
    }
    // ── New tools ──────────────────────────────────────────────────────────
    case 'get_software_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid software ID format' };
      return callInternalApi(`/software/${id}`);
    }
    case 'search_software': {
      const params = new URLSearchParams();
      const s = sanitizeSearch(args.search);
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/software?${params}`);
    }
    case 'get_campaign_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid campaign ID format' };
      return callInternalApi(`/campaigns/${id}`);
    }
    case 'search_campaigns': {
      const params = new URLSearchParams();
      const s = sanitizeSearch(args.search);
      if (s.length >= 3) params.set('search', s);
      const sec = validateSector(args.sector);
      if (sec) params.set('sector', sec);
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/campaigns?${params}`);
    }
    case 'get_mitigation_detail': {
      const id = validateAttackId(args.attack_id);
      if (!id) return { error: 'Invalid mitigation ID format' };
      return callInternalApi(`/mitigations/${id}`);
    }
    case 'search_mitigations': {
      const params = new URLSearchParams();
      const s = sanitizeSearch(args.search);
      if (s.length >= 3) params.set('search', s);
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 10, 1), 50)));
      return callInternalApi(`/mitigations?${params}`);
    }
    case 'search_iocs': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.type) params.set('type', String(args.type));
      if (args.source) params.set('source', String(args.source));
      if (args.malware) params.set('malware', sanitizeSearch(args.malware));
      if (args.since) {
        const d = new Date(String(args.since));
        if (!isNaN(d.getTime())) params.set('since', d.toISOString());
      }
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 20, 1), 100)));
      return callInternalApi(`/feed/iocs?${params}`);
    }
    case 'search_sigma_rules': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (tid) params.set('technique', tid);
      }
      if (args.level) params.set('level', String(args.level).toLowerCase());
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 20, 1), 100)));
      return callInternalApi(`/feed/sigma?${params}`);
    }
    case 'search_atomic_tests': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', sanitizeSearch(args.q));
      if (args.technique) {
        const tid = validateAttackId(args.technique);
        if (tid) params.set('technique', tid);
      }
      if (args.platform) params.set('platform', String(args.platform).toLowerCase());
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 20, 1), 100)));
      return callInternalApi(`/feed/atomic?${params}`);
    }
    case 'get_external_actor': {
      const n = sanitizeSearch(args.name);
      if (n.length < 2) return { error: 'Actor name must be at least 2 characters' };
      return callInternalApi(`/external-actors/${encodeURIComponent(n)}`);
    }
    case 'search_external_actors': {
      const params = new URLSearchParams();
      const s = sanitizeSearch(args.search);
      if (s.length >= 2) params.set('search', s);
      if (args.country) params.set('country', String(args.country));
      if (args.category) params.set('category', String(args.category));
      params.set('limit', String(Math.min(Math.max(Number(args.limit) || 20, 1), 100)));
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
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ── Rate limiting ────────────────────────────────────────────────────────────

function getClientIp(req: VercelRequest): string {
  const realIp = req.headers['x-real-ip'];
  if (typeof realIp === 'string') return realIp.trim();
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string') return forwarded.split(',')[0].trim();
  return req.socket?.remoteAddress ?? 'unknown';
}

async function checkRateLimit(ip: string): Promise<{ allowed: boolean; remaining: number }> {
  const result = await query<{ count: string }>(
    `SELECT COUNT(*) FROM a2a_requests WHERE ip = $1 AND requested_at > NOW() - INTERVAL '24 hours'`,
    [ip],
  );
  const used = parseInt(result.rows[0].count, 10);
  return { allowed: used < DAILY_LIMIT, remaining: Math.max(0, DAILY_LIMIT - used) };
}

interface A2aLog {
  ip: string;
  userQuery: string | null;
  skillId: string | null;
  toolsCalled: string[];
  responseText: string | null;
  tokensUsed: number;
  latencyMs: number;
  error: string | null;
}

async function recordRequest(log: A2aLog): Promise<void> {
  try {
    await query(
      `INSERT INTO a2a_requests (ip, user_query, skill_id, tools_called, response_text, tokens_used, latency_ms, error)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [log.ip, log.userQuery, log.skillId, log.toolsCalled, log.responseText, log.tokensUsed, log.latencyMs, log.error],
    );
  } catch { /* non-fatal */ }
}

// ── JSON-RPC handler ─────────────────────────────────────────────────────────

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

function jsonRpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method not allowed' }); return; }

  const body = req.body as JsonRpcRequest;
  if (!body?.jsonrpc || body.jsonrpc !== '2.0' || !body.method) {
    res.status(400).json(jsonRpcError(body?.id ?? null, -32600, 'Invalid JSON-RPC request'));
    return;
  }

  // Validate body.id
  const reqId = typeof body.id === 'string' ? body.id.slice(0, 100) : typeof body.id === 'number' ? body.id : null;
  if (reqId === null) {
    res.status(400).json(jsonRpcError(null, -32600, 'Missing or invalid request id'));
    return;
  }

  const ip = getClientIp(req);

  // Rate limit — fail-closed on DB errors
  let remaining = DAILY_LIMIT;
  try {
    const rl = await checkRateLimit(ip);
    remaining = rl.remaining;
    if (!rl.allowed) {
      res.setHeader('Retry-After', '86400');
      res.setHeader('X-RateLimit-Limit', DAILY_LIMIT);
      res.setHeader('X-RateLimit-Remaining', 0);
      res.status(429).json(jsonRpcError(reqId, -32000, `Rate limit exceeded. ${DAILY_LIMIT} requests/day per IP.`));
      return;
    }
  } catch {
    res.status(503).json(jsonRpcError(reqId, -32603, 'Service temporarily unavailable'));
    return;
  }
  res.setHeader('X-RateLimit-Limit', DAILY_LIMIT);
  res.setHeader('X-RateLimit-Remaining', remaining);

  // Accept both v1.0 (PascalCase) and v0.x (slash) method names
  if (body.method === 'SendMessage' || body.method === 'message/send') {
    const message = body.params?.message as { role?: string; parts?: Array<{ text?: string }> } | undefined;
    let userText = message?.parts?.[0]?.text;

    if (!userText) {
      res.status(400).json(jsonRpcError(reqId, -32602, 'Missing message.parts[0].text'));
      return;
    }

    if (userText.length > MAX_INPUT_LENGTH) {
      userText = userText.slice(0, MAX_INPUT_LENGTH);
    }

    const startMs = Date.now();

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(500).json(jsonRpcError(reqId, -32603, 'AI service unavailable'));
        return;
      }

      const ai = new GoogleGenAI({ apiKey });
      const toolsConfig = [{ functionDeclarations: TOOL_DECLARATIONS as any }];

      // Initial Gemini call with function declarations
      const response = await ai.models.generateContent({
        model: MODEL,
        contents: [{ role: 'user', parts: [{ text: userText }] }],
        config: { systemInstruction: SYSTEM_INSTRUCTION, tools: toolsConfig },
      });

      const candidate = response.candidates?.[0];
      const parts = candidate?.content?.parts ?? [];
      const functionCalls = parts.filter((p) => p.functionCall);

      let finalText: string;
      const skillsUsed: string[] = [];
      let totalTokens = response.usageMetadata?.totalTokenCount ?? 0;
      let rawToolData: Record<string, unknown>[] = [];

      if (functionCalls.length > 0) {
        // Execute all tool calls in parallel
        const toolResults = await Promise.all(
          functionCalls.map(async (fc) => {
            const toolName = fc.functionCall!.name!;
            const toolArgs = (fc.functionCall!.args ?? {}) as Record<string, unknown>;
            skillsUsed.push(toolName);
            const result = await executeTool(toolName, toolArgs);
            return { name: toolName, id: fc.functionCall!.id, args: toolArgs, result };
          }),
        );

        // Capture raw API results for structured artifact
        rawToolData = toolResults.map((tr) => ({ tool: tr.name, args: tr.args, data: tr.result }));

        // Build follow-up: pass original model parts verbatim to preserve function call IDs
        const followUp = await ai.models.generateContent({
          model: MODEL,
          contents: [
            { role: 'user' as const, parts: [{ text: userText }] },
            { role: 'model' as const, parts },
            { role: 'user' as const, parts: toolResults.map((tr) => ({
              functionResponse: { name: tr.name, id: tr.id, response: { output: tr.result } },
            })) },
          ],
          config: { systemInstruction: SYSTEM_INSTRUCTION, tools: toolsConfig },
        });

        totalTokens += followUp.usageMetadata?.totalTokenCount ?? 0;
        finalText = followUp.text ?? 'No response generated.';
      } else {
        finalText = response.text ?? 'No response generated.';
      }

      await recordRequest({
        ip, userQuery: userText, skillId: skillsUsed[0] ?? null,
        toolsCalled: skillsUsed, responseText: finalText.slice(0, 4000),
        tokensUsed: totalTokens, latencyMs: Date.now() - startMs, error: null,
      });

      const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const now = new Date().toISOString();

      // Build artifacts: text summary + structured JSON data
      const artifacts: Array<Record<string, unknown>> = [];
      if (skillsUsed.length > 0) {
        // Human-readable summary
        artifacts.push({
          artifactId: `${taskId}-summary`,
          name: 'summary',
          description: 'Human-readable response with markdown links',
          parts: [{ text: finalText }],
        });
        // Structured API data — machine-parseable
        artifacts.push({
          artifactId: `${taskId}-data`,
          name: 'structured_data',
          description: 'Raw API results as structured JSON for downstream parsing',
          parts: [{ data: rawToolData, mediaType: 'application/json' }],
        });
      }

      res.status(200).json({
        jsonrpc: '2.0',
        id: reqId,
        result: {
          id: taskId,
          contextId: taskId,
          status: {
            state: 'completed',
            message: { role: 'agent', parts: [{ text: finalText }] },
            timestamp: now,
          },
          history: [
            { role: 'user', parts: [{ text: userText }] },
            { role: 'agent', parts: [{ text: finalText }] },
          ],
          artifacts,
          metadata: { tokensUsed: totalTokens, toolsCalled: skillsUsed },
          createdAt: now,
          updatedAt: now,
        },
      });
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error('A2A error:', errMsg);
      await recordRequest({
        ip, userQuery: userText, skillId: null, toolsCalled: [],
        responseText: null, tokensUsed: 0, latencyMs: Date.now() - startMs, error: errMsg.slice(0, 1000),
      });
      res.status(500).json(jsonRpcError(reqId, -32603, 'Internal error processing request'));
    }
  } else {
    res.status(400).json(jsonRpcError(reqId, -32601, 'Method not supported. Use SendMessage'));
  }
}
