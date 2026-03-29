import type { VercelRequest, VercelResponse } from '@vercel/node';
import { GoogleGenAI } from '@google/genai';
import { query } from '../v1/lib/db.js';

/**
 * A2A (Agent-to-Agent) endpoint — JSON-RPC 2.0 over HTTPS.
 * Accepts natural language queries, uses Gemini 3.1 Flash-Lite to interpret,
 * calls internal APIs, returns structured results.
 *
 * Rate limit: 50 req/day per IP, no auth required.
 */

const DAILY_LIMIT = 50;
const MODEL = 'gemini-3.1-flash-lite-preview';
const BASE_URL = process.env.VERCEL_URL
  ? `https://${process.env.VERCEL_URL}`
  : 'https://mitre-explorer.org';

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
    description: 'Search threat groups by name or description. Returns group ID, name, and technique count.',
    parameters: {
      type: "OBJECT",
      properties: {
        search: { type: "STRING", description: 'Search keyword' },
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
    description: 'Cross-domain search across all entity types: techniques, groups, software, campaigns, mitigations, data sources, applications.',
    parameters: {
      type: "OBJECT",
      properties: {
        q: { type: "STRING", description: 'Search query' },
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
];

// ── Internal API caller ──────────────────────────────────────────────────────

async function callInternalApi(path: string): Promise<unknown> {
  const url = `${BASE_URL}/api/v1${path}`;
  const resp = await fetch(url, { headers: { 'Accept': 'application/json' } });
  if (!resp.ok) return { error: `API returned ${resp.status}`, path };
  return resp.json();
}

async function executeTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case 'search_cves': {
      const params = new URLSearchParams();
      if (args.q) params.set('q', String(args.q));
      if (args.severity) params.set('severity', String(args.severity));
      if (args.since) params.set('since', String(args.since));
      params.set('limit', String(Math.min(Number(args.limit) || 10, 50)));
      return callInternalApi(`/cves?${params}`);
    }
    case 'get_cve_detail':
      return callInternalApi(`/cves/${args.cve_id}`);
    case 'get_technique_intelligence':
      return callInternalApi(`/feed/intelligence/${args.attack_id}`);
    case 'get_technique_detail':
      return callInternalApi(`/techniques/${args.attack_id}`);
    case 'get_group_profile':
      return callInternalApi(`/groups/${args.attack_id}`);
    case 'search_groups': {
      const params = new URLSearchParams();
      if (args.search) params.set('search', String(args.search));
      if (args.sector) params.set('sector', String(args.sector));
      if (args.domain) params.set('domain', String(args.domain));
      params.set('limit', String(Math.min(Number(args.limit) || 10, 50)));
      return callInternalApi(`/groups?${params}`);
    }
    case 'get_application_security': {
      const v = String(args.vendor).toLowerCase().replace(/[^a-z0-9]/g, '');
      const p = String(args.product).toLowerCase().replace(/[^a-z0-9]/g, '');
      return callInternalApi(`/applications/${v}/${p}`);
    }
    case 'search_applications': {
      const params = new URLSearchParams();
      if (args.search) params.set('search', String(args.search));
      params.set('limit', String(Math.min(Number(args.limit) || 10, 50)));
      return callInternalApi(`/applications?${params}`);
    }
    case 'get_sector_threats':
      return callInternalApi(`/sectors/${args.sector}/relationships`);
    case 'search_entities':
      return callInternalApi(`/entities?q=${encodeURIComponent(String(args.q))}`);
    case 'get_dashboard_stats': {
      const params = new URLSearchParams();
      if (args.domain) params.set('domain', String(args.domain));
      if (args.sector) params.set('sector', String(args.sector));
      return callInternalApi(`/dashboard?${params}`);
    }
    case 'get_framework_mappings':
      return callInternalApi(`/frameworks/technique/${args.attack_id}`);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ── Rate limiting ────────────────────────────────────────────────────────────

function getClientIp(req: VercelRequest): string {
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

async function recordRequest(ip: string, skillId: string | null, tokensUsed: number): Promise<void> {
  await query(
    `INSERT INTO a2a_requests (ip, skill_id, tokens_used) VALUES ($1, $2, $3)`,
    [ip, skillId, tokensUsed],
  );
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
  // CORS
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

  const ip = getClientIp(req);

  // Rate limit check
  const { allowed, remaining } = await checkRateLimit(ip);
  res.setHeader('X-RateLimit-Limit', DAILY_LIMIT);
  res.setHeader('X-RateLimit-Remaining', remaining);
  if (!allowed) {
    res.setHeader('Retry-After', '86400');
    res.status(429).json(jsonRpcError(body.id, -32000, `Rate limit exceeded. ${DAILY_LIMIT} requests/day per IP. Retry after 24 hours.`));
    return;
  }

  if (body.method === 'message/send') {
    const message = body.params?.message as { role?: string; parts?: Array<{ text?: string }> } | undefined;
    const userText = message?.parts?.[0]?.text;

    if (!userText) {
      res.status(400).json(jsonRpcError(body.id, -32602, 'Missing message.parts[0].text'));
      return;
    }

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        res.status(500).json(jsonRpcError(body.id, -32603, 'GEMINI_API_KEY not configured'));
        return;
      }

      const ai = new GoogleGenAI({ apiKey });

      // Initial Gemini call with function declarations
      const response = await ai.models.generateContent({
        model: MODEL,
        contents: [
          {
            role: 'user',
            parts: [{ text: userText }],
          },
        ],
        config: {
          systemInstruction: `You are the MITRE Explorer threat intelligence agent. You help security professionals, SOC analysts, and AI agents query the MITRE ATT&CK knowledge base, CVE vulnerabilities, and application security data.

Use the available tools to answer questions. Always call a tool before answering — never guess or hallucinate data. If the user asks about a CVE, technique, group, or application, look it up.

When responding:
- Be concise and factual
- Include ATT&CK IDs (e.g. T1059, G0016) when relevant
- Include CVE IDs when relevant
- Mention severity levels for CVEs
- Reference specific data counts when available`,
          tools: [{ functionDeclarations: TOOL_DECLARATIONS as any }],
        },
      });

      // Check if Gemini wants to call a function
      const candidate = response.candidates?.[0];
      const parts = candidate?.content?.parts ?? [];
      const functionCall = parts.find((p) => p.functionCall);

      let finalText: string;
      let skillUsed: string | null = null;

      if (functionCall?.functionCall) {
        // Execute the tool
        const toolName = functionCall.functionCall.name!;
        const toolArgs = (functionCall.functionCall.args ?? {}) as Record<string, unknown>;
        skillUsed = toolName;

        const toolResult = await executeTool(toolName, toolArgs);

        // Send tool result back to Gemini for summarization
        const followUp = await ai.models.generateContent({
          model: MODEL,
          contents: [
            { role: 'user' as const, parts: [{ text: userText }] },
            { role: 'model' as const, parts: [{ functionCall: { name: toolName, args: toolArgs } }] },
            { role: 'user' as const, parts: [{ functionResponse: { name: toolName, response: toolResult as Record<string, unknown> } }] },
          ],
          config: {
            systemInstruction: `You are the MITRE Explorer threat intelligence agent. Summarize the tool results concisely for the user. Include specific data points, IDs, and counts. Format as structured text.`,
          },
        });

        finalText = followUp.candidates?.[0]?.content?.parts?.[0]?.text ?? 'No response generated.';
      } else {
        // Direct response (no tool call needed)
        finalText = parts[0]?.text ?? 'No response generated.';
      }

      // Record the request
      await recordRequest(ip, skillUsed, finalText.length);

      // A2A Task response
      const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      res.status(200).json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          id: taskId,
          status: {
            state: 'completed',
            message: {
              role: 'agent',
              parts: [{ text: finalText }],
            },
            timestamp: new Date().toISOString(),
          },
          artifacts: skillUsed ? [{
            artifactId: `${skillUsed}-result`,
            name: skillUsed,
            parts: [{ text: finalText }],
          }] : [],
        },
      });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('A2A error:', msg);
      await recordRequest(ip, null, 0);
      res.status(500).json(jsonRpcError(body.id, -32603, 'Internal error processing request'));
    }
  } else {
    res.status(400).json(jsonRpcError(body.id, -32601, `Method not found: ${body.method}. Supported: message/send`));
  }
}
