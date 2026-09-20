import { NextRequest, NextResponse } from 'next/server';
import { createHash, timingSafeEqual } from 'node:crypto';
import { query } from '../v1/lib/db';
import { withCorsRestricted, corsOptionsRestricted } from '../lib/cors';
import { TOOL_DECLARATIONS, executeTool } from '../../../src/lib/tools';

// A2A uses restricted CORS (origin allowlist) to prevent cross-origin browser
// pages from silently consuming a victim user's 50-req/day quota.
export async function OPTIONS(req: NextRequest) { return corsOptionsRestricted(req); }

/**
 * A2A (Agent-to-Agent) endpoint -- JSON-RPC 2.0 over HTTPS.
 * Accepts natural language queries, uses Gemini 3.1 Flash-Lite to interpret,
 * calls internal APIs, returns structured results.
 *
 * Rate limit: 50 req/day per IP, no auth required. Callers presenting a
 * valid A2A_API_KEY (`Authorization: Bearer <key>`) bypass the limit.
 */

const DAILY_LIMIT = 50;
const MODEL = 'gemini-3.1-flash-lite-preview';
const MAX_INPUT_LENGTH = 2000;

// -- Gemini REST client ------------------------------------------------------
// Called directly rather than through @google/genai. That SDK was the only
// thing pulling protobufjs and ws into the tree (critical / high advisories
// respectively, neither reachable from our one endpoint but both permanently
// red in `npm audit`), and we use exactly one method of it. The shapes below
// are the REST wire format -- which is what the SDK handed back anyway, minus
// its `.text` convenience getter (reimplemented as geminiText).

const GEMINI_API = 'https://generativelanguage.googleapis.com/v1beta/models';
/**
 * Per-call ceiling. Raw fetch has no timeout of its own, and the SDK's
 * models.generateContent path never had one either (httpOptions.timeout and
 * retryOptions are opt-in and were never set), so nothing bounded these calls
 * before. Net-new behaviour, not a restoration.
 */
const GEMINI_TIMEOUT_MS = 30_000;

interface GeminiFunctionCall {
  name?: string;
  id?: string;
  args?: Record<string, unknown>;
}

interface GeminiPart {
  text?: string;
  functionCall?: GeminiFunctionCall;
}

interface GeminiResponse {
  candidates?: Array<{ content?: { parts?: GeminiPart[] } }>;
  usageMetadata?: { totalTokenCount?: number };
}

/**
 * One `models.generateContent` call.
 *
 * Note the reshaping: the SDK accepted `systemInstruction` as a bare string
 * nested under `config`, while REST wants a Content object at the top level.
 */
async function generateContent(opts: {
  apiKey: string;
  contents: unknown;
  systemInstruction: string;
  tools: unknown;
}): Promise<GeminiResponse> {
  const res = await fetch(`${GEMINI_API}/${MODEL}:generateContent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-goog-api-key': opts.apiKey },
    body: JSON.stringify({
      contents: opts.contents,
      systemInstruction: { parts: [{ text: opts.systemInstruction }] },
      tools: opts.tools,
    }),
    signal: AbortSignal.timeout(GEMINI_TIMEOUT_MS),
  });

  if (!res.ok) {
    // Body may carry the reason (bad key, quota, safety block). Truncate it:
    // this string reaches recordRequest() and the JSON-RPC error path.
    const detail = await res.text().catch(() => '');
    throw new Error(`Gemini ${res.status}: ${detail.slice(0, 200)}`);
  }
  return (await res.json()) as GeminiResponse;
}

/** Parity with the SDK's `.text`: concatenate every text part of candidate 0. */
function geminiText(r: GeminiResponse): string {
  return (r.candidates?.[0]?.content?.parts ?? []).map((p) => p.text ?? '').join('');
}

// Dynamic system instruction -- injects current date so Gemini calculates relative dates correctly
function buildSystemInstruction(): string {
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  return `You are the MITRE Explorer threat intelligence agent. You help security professionals, SOC analysts, and AI agents query the MITRE ATT&CK knowledge base, CVE vulnerabilities, and application security data.

IMPORTANT: Today's date is ${today}. Always use this date for relative time calculations (e.g. "last 7 days" means since ${new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0]}). Never assume a different year.

Use the available tools to answer questions. Always call a tool before answering -- never guess or hallucinate data.

Tool selection rules:
- When asked about a SPECIFIC group (e.g. "Lazarus Group", "APT29"): use search_groups to find the ID, then get_group_profile for the full profile
- When asked about a SPECIFIC technique: use get_technique_detail for description + get_technique_intelligence for feeds
- When asked about a SPECIFIC software/malware: use search_software to find the ID, then get_software_detail
- When asked about a SPECIFIC CAPEC attack pattern (e.g. "CAPEC-66", "SQL Injection attack pattern"): use get_capec_detail; to list/filter patterns use search_capec
- When asked about a SPECIFIC OSV / distro / kernel advisory (DSA-*, USN-*, ALAS-*, RLSA-*, LBSEC-*, etc.): use get_osv_detail
- When asked about advisories broadly ("show me recent Debian advisories", "which Alpine CVEs this week", "OSS package vulnerabilities for npm"): use search_advisories with the ecosystem / source filter. This unifies GHSA (OSS packages) + OSV (OS/distros/kernels) into one list.
- For GHSA-specific advisory detail (e.g. "GHSA-jfh8-c2jp-5v3q"): use get_ghsa_detail. For Debian/Ubuntu/Alpine/kernel advisories: use get_osv_detail.
- For "what CVEs affect product X version Y" / "is X version Y affected": use search_cves with app=X and version=Y, or get_application_security with vendor/product/version. For the same question about an OSS PACKAGE or a GHSA advisory, use get_package_vulnerabilities (ecosystem + package_name + version) or get_ghsa_detail (ghsa_id + version). The version filter is a SUBSTRING/TEXT match against the affected-version range (the data is free-text) — it surfaces entries that MENTION that version string, NOT a definitive "this exact version is vulnerable" verdict. State this caveat; never claim a version is confirmed vulnerable or safe based solely on it.
- "search_" tools return summaries/lists; "get_" tools return full profiles -- always prefer the full profile for specific entities
- For OWASP categories: use get_owasp_top10 (optionally filtered by framework: web-2021, ml-2023, llm-2025), then get_owasp_category for details
- OWASP links: [A01 Broken Access Control](https://mitre-explorer.org/frameworks/owasp/A01)
- For COMPLIANCE / regulatory questions (NIS2, DORA, PCI DSS, ISO 27002, HIPAA, GDPR, CMMC, FedRAMP, EU CRA, EU AI Act, OWASP Top 10, etc.): use list_compliance_frameworks to discover, get_compliance_framework for a single framework's techniques and articles, get_technique_compliance to find which frameworks reference a given T-ID. These are bridged to ATT&CK via the Secure Controls Framework (SCF, CC BY 4.0). Curated default = 21 Tier 1+2 frameworks; pass include_all=true for the ~250 long-tail. Coverage is FINITE — if a framework or framework/technique pair returns no data, state explicitly that the SCF crosswalk does not cover it; never infer a mapping. Compliance link example: [EU NIS2](https://mitre-explorer.org/compliance/eu-nis2).
- EXCEPTION: for a technique's NIST 800-53 controls, MITRE Engage activities, VERIS categories, or AWS/Azure/GCP cloud controls, use get_framework_mappings (direct per-technique mappings) — NOT the SCF compliance tools, which cover 800-53 only as one regulatory cross-reference among ~250.
- You MUST generate a human-readable summary from the tool results -- never return empty or "No response generated"

When responding:
- Be concise and factual
- For EVERY CVE mentioned, always include: CVE ID, CVSS score, severity (CRITICAL/HIGH/MEDIUM/LOW), published date, and linked ATT&CK techniques if available
- If the CVE detail response includes epssScore and epssPercentile, surface them: "EPSS: 0.94 (97th percentile)" means 94% predicted exploitation in 30 days and ranked in top 3% of all scored CVEs. Omit cleanly when null.
- If the CVE / GHSA / technique detail response includes capecPatterns, list them by CAPEC ID with severity (e.g. "CAPEC-66 SQL Injection — High severity") and link to [CAPEC-66](https://mitre-explorer.org/cti/capec/CAPEC-66)
- If the CVE detail response includes an osvAdvisories array (distro/kernel advisories aliasing the CVE), surface them grouped by ecosystem with a short list per ecosystem. E.g. "Also affected: Debian ([DSA-5678-1](https://mitre-explorer.org/cti/osv/DSA-5678-1)), Ubuntu ([USN-6543-1](https://mitre-explorer.org/cti/osv/USN-6543-1)), Alpine, ..."
- Include clickable markdown links to MITRE Explorer for every entity mentioned:
  - CVEs: [CVE-2024-3400](https://mitre-explorer.org/cti/cves/CVE-2024-3400)
  - Techniques: [T1059](https://mitre-explorer.org/techniques/T1059)
  - Groups: [APT29](https://mitre-explorer.org/?entity=G0016&tab=actor)
  - Applications: [LiteLLM](https://mitre-explorer.org/?entity=litellm%2Flitellm&tab=application-map)
  - CAPEC patterns: [CAPEC-66 SQL Injection](https://mitre-explorer.org/cti/capec/CAPEC-66)
  - OSV advisories: [DSA-5678-1](https://mitre-explorer.org/cti/osv/DSA-5678-1)
  - Unified advisories list: [advisories for Debian](https://mitre-explorer.org/cti/advisories?source=OSV&ecosystem=Debian)
- Use tables for structured data when listing multiple items
- Always mention total result count (e.g. "Showing 10 of 47 results")
- Keep a consistent schema per entity type -- do not change column layout between responses
- Do not truncate CVE descriptions mid-sentence -- include the full description or summarize it cleanly
- When reporting CVEs, add this note at the end: "NVD typically adds CPE entries days after CVE publication -- recent CVEs may show empty until enriched."
- For each CVE with linked techniques, list the technique IDs (e.g. T1190, T1059) -- these are the bridge between a vulnerability and the actual attack behaviour it enables
- For each CVE, include the affected applications if available (the "applications" field in the response) -- this tells the user which products are impacted
- When showing date ranges in your response, always confirm the actual dates used (e.g. "CVEs published between 2026-03-22 and 2026-03-29")`;
}

// -- Rate limiting ------------------------------------------------------------

/**
 * Static salt used to hash client IPs before they touch the database. The raw
 * IP is never persisted — only the salted SHA-256, which is sufficient for
 * rate-limit bucketing but pseudonymous under GDPR (Art. 4(5)).
 *
 * Set A2A_IP_SALT in the Vercel environment. In local dev, a fallback is used
 * with a loud warning; this is NOT GDPR-compliant for production, but lets
 * tests and local development work without extra setup.
 */
const IP_SALT = process.env.A2A_IP_SALT || (() => {
  console.warn('[a2a] A2A_IP_SALT is not set — using insecure fallback. Set the env var in production.');
  return 'dev-only-insecure-salt';
})();

function getRawClientIp(req: NextRequest): string {
  // Trust only infrastructure-set headers — never the user-supplied
  // `x-forwarded-for` (an attacker can spoof it to rotate through "fresh"
  // IPs and bypass the 50-req/day quota).
  //
  // Header precedence:
  //   1. `cf-connecting-ip` — set by Cloudflare when the zone is proxied.
  //      Cloudflare overwrites/strips a client-supplied value, so it's the
  //      true client IP whenever we sit behind Cloudflare. Must be checked
  //      FIRST, because with Cloudflare in front Vercel's own headers would
  //      otherwise show Cloudflare's edge IP and bucket every caller together.
  //   2. `x-vercel-forwarded-for` — Vercel edge, real client IP (direct-to-Vercel).
  //   3. `x-real-ip` — legacy Vercel.
  const cfIp = req.headers.get('cf-connecting-ip');
  if (cfIp) return cfIp.trim();
  const vercelIp = req.headers.get('x-vercel-forwarded-for');
  if (vercelIp) return vercelIp.split(',')[0].trim();
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  // Fallback to last hop of x-forwarded-for — Vercel appends the real IP at
  // the end if they forward the header at all.
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const hops = forwarded.split(',').map((s) => s.trim()).filter(Boolean);
    return hops[hops.length - 1] ?? 'unknown';
  }
  return 'unknown';
}

/**
 * Returns a salted SHA-256 hex digest of the client IP. Stable across
 * requests (so rate-limit counts aggregate correctly) but irreversible
 * without the salt. The raw IP is never stored or logged by this module.
 */
function getClientIpHash(req: NextRequest): string {
  const raw = getRawClientIp(req);
  return createHash('sha256').update(IP_SALT).update(':').update(raw).digest('hex');
}

/**
 * Optional rate-limit bypass for trusted callers (own side-projects,
 * server-to-server integrations). Set A2A_API_KEY in the Vercel environment
 * and send `Authorization: Bearer <key>`. Unset → no bypass possible (never
 * fail-open). Bypassed requests are still logged to a2a_requests.
 */
const API_KEY = process.env.A2A_API_KEY || null;

function hasValidApiKey(req: NextRequest): boolean {
  if (!API_KEY) return false;
  const provided = String(req.headers.get('authorization') ?? '');
  const expected = `Bearer ${API_KEY}`;
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(Buffer.from(provided), Buffer.from(expected));
}

async function checkRateLimit(ipHash: string): Promise<{ allowed: boolean; remaining: number }> {
  const result = await query<{ count: string }>(
    `SELECT COUNT(*) FROM a2a_requests WHERE ip = $1 AND requested_at > NOW() - INTERVAL '24 hours'`,
    [ipHash],
  );
  const used = parseInt(result.rows[0].count, 10);
  return { allowed: used < DAILY_LIMIT, remaining: Math.max(0, DAILY_LIMIT - used) };
}

interface A2aLog {
  /** Salted SHA-256 hash of the client IP — never the raw address. */
  ipHash: string;
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
      [log.ipHash, log.userQuery, log.skillId, log.toolsCalled, log.responseText, log.tokensUsed, log.latencyMs, log.error],
    );
  } catch (e) {
    console.error('A2A log write failed:', e instanceof Error ? e.message : e);
  }
}

// -- JSON-RPC handler ---------------------------------------------------------

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

function jsonRpcError(id: string | number | null, code: number, message: string) {
  return { jsonrpc: '2.0', id, error: { code, message } };
}

export async function POST(req: NextRequest) {
  // Origin-restricted CORS closure — stays in scope for all response returns below.
  const withCors = (resp: NextResponse) => withCorsRestricted(resp, req);

  // Parse defensively: an unparseable body threw out of the handler and surfaced
  // as a 500, which reads as "the server is broken" to a caller that simply sent
  // bad JSON. JSON-RPC has a code for exactly this.
  let body: JsonRpcRequest;
  try {
    body = (await req.json()) as JsonRpcRequest;
  } catch {
    return withCors(NextResponse.json(jsonRpcError(null, -32700, 'Parse error'), { status: 400 }));
  }

  // Note: an array body (a JSON-RPC batch) fails the check below and is
  // rejected. That is deliberate -- unlike MCP, this endpoint never fans out.
  if (!body?.jsonrpc || body.jsonrpc !== '2.0' || !body.method) {
    return withCors(NextResponse.json(
      jsonRpcError(body?.id ?? null, -32600, 'Invalid JSON-RPC request'),
      { status: 400 },
    ));
  }

  // Validate body.id
  const reqId = typeof body.id === 'string' ? body.id.slice(0, 100) : typeof body.id === 'number' ? body.id : null;
  if (reqId === null) {
    return withCors(NextResponse.json(
      jsonRpcError(null, -32600, 'Missing or invalid request id'),
      { status: 400 },
    ));
  }

  const ipHash = getClientIpHash(req);
  const bypassRateLimit = hasValidApiKey(req);

  // Rate limit -- fail-closed on DB errors. Skipped for callers presenting a
  // valid A2A_API_KEY (see hasValidApiKey); their requests are still logged.
  let remaining = DAILY_LIMIT;
  if (!bypassRateLimit) {
    try {
      const rl = await checkRateLimit(ipHash);
      remaining = rl.remaining;
      if (!rl.allowed) {
        const resp = NextResponse.json(
          jsonRpcError(reqId, -32000, `Rate limit exceeded. ${DAILY_LIMIT} requests/day per IP.`),
          { status: 429 },
        );
        resp.headers.set('Retry-After', '86400');
        resp.headers.set('X-RateLimit-Limit', String(DAILY_LIMIT));
        resp.headers.set('X-RateLimit-Remaining', '0');
        return withCors(resp);
      }
    } catch {
      return withCors(NextResponse.json(
        jsonRpcError(reqId, -32603, 'Service temporarily unavailable'),
        { status: 503 },
      ));
    }
  }

  // Accept both v1.0 (PascalCase) and v0.x (slash) method names
  if (body.method === 'SendMessage' || body.method === 'message/send') {
    const message = body.params?.message as { role?: string; parts?: Array<{ text?: string }> } | undefined;
    let userText = message?.parts?.[0]?.text;

    if (!userText) {
      return withCors(NextResponse.json(
        jsonRpcError(reqId, -32602, 'Missing message.parts[0].text'),
        { status: 400 },
      ));
    }

    if (userText.length > MAX_INPUT_LENGTH) {
      userText = userText.slice(0, MAX_INPUT_LENGTH);
    }

    const startMs = Date.now();

    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (!apiKey) {
        return withCors(NextResponse.json(
          jsonRpcError(reqId, -32603, 'AI service unavailable'),
          { status: 500 },
        ));
      }

      const toolsConfig = [{ functionDeclarations: TOOL_DECLARATIONS as any }];
      // Hoist once per request — the function is pure modulo today's date,
      // which doesn't change across the agentic loop (max 4 calls / request).
      const systemInstruction = buildSystemInstruction();

      // Initial Gemini call with function declarations
      const response = await generateContent({
        apiKey,
        contents: [{ role: 'user', parts: [{ text: userText }] }],
        systemInstruction,
        tools: toolsConfig,
      });

      const candidate = response.candidates?.[0];
      const parts = candidate?.content?.parts ?? [];
      const functionCalls = parts.filter((p) => p.functionCall);

      let finalText = '';
      const skillsUsed: string[] = [];
      let totalTokens = response.usageMetadata?.totalTokenCount ?? 0;
      let rawToolData: Record<string, unknown>[] = [];

      if (functionCalls.length > 0) {
        // Execute tool calls in parallel (cap at 5)
        const capped = functionCalls.slice(0, 5);
        const settled = await Promise.allSettled(
          capped.map(async (fc) => {
            const toolName = fc.functionCall!.name!;
            const toolArgs = (fc.functionCall!.args ?? {}) as Record<string, unknown>;
            skillsUsed.push(toolName);
            const result = await executeTool(toolName, toolArgs);
            return { name: toolName, id: fc.functionCall!.id, args: toolArgs, result };
          }),
        );
        const toolResults = settled.map((s, i) =>
          s.status === 'fulfilled'
            ? s.value
            : { name: capped[i].functionCall!.name!, id: capped[i].functionCall!.id, args: {}, result: { error: `Tool failed: ${(s.reason as Error)?.message ?? 'unknown'}` } },
        );

        // Capture full raw API results for structured artifact
        rawToolData = toolResults.map((tr) => ({ tool: tr.name, args: tr.args, data: tr.result }));

        // Trim tool results for Gemini context -- full data stays in rawToolData for the artifact
        const trimmedForGemini = toolResults.map((tr) => {
          const json = JSON.stringify(tr.result);
          if (json.length <= 4000) return tr;
          // Truncate: keep top-level scalars, trim arrays to first 5 items
          const trimmed: Record<string, unknown> = {};
          for (const [k, v] of Object.entries(tr.result)) {
            if (Array.isArray(v)) {
              trimmed[k] = v.slice(0, 5);
              if (v.length > 5) trimmed[`${k}_total`] = v.length;
            } else {
              trimmed[k] = v;
            }
          }
          return { ...tr, result: trimmed };
        });

        // Agentic loop: Gemini may chain tools (search -> get_profile). Max 3 rounds.
        let conversationParts: Array<{ role: string; parts: unknown[] }> = [
          { role: 'user', parts: [{ text: userText }] },
          { role: 'model', parts },
          { role: 'user', parts: trimmedForGemini.map((tr) => ({
            functionResponse: { name: tr.name, id: tr.id, response: { output: tr.result } },
          })) },
        ];

        for (let round = 0; round < 3; round++) {
          const followUp = await generateContent({
            apiKey,
            contents: conversationParts,
            systemInstruction,
            tools: toolsConfig,
          });

          totalTokens += followUp.usageMetadata?.totalTokenCount ?? 0;
          const followParts = followUp.candidates?.[0]?.content?.parts ?? [];
          const moreCalls = followParts.filter((p) => p.functionCall);

          if (moreCalls.length === 0) {
            // No more tool calls -- extract text
            const followText = followParts.find((p) => p.text)?.text;
            finalText = followText ?? geminiText(followUp);
            break;
          }

          // Execute next round of tool calls
          const nextCapped = moreCalls.slice(0, 3);
          const nextSettled = await Promise.allSettled(
            nextCapped.map(async (fc) => {
              const toolName = fc.functionCall!.name!;
              const toolArgs = (fc.functionCall!.args ?? {}) as Record<string, unknown>;
              skillsUsed.push(toolName);
              const result = await executeTool(toolName, toolArgs);
              return { name: toolName, id: fc.functionCall!.id, args: toolArgs, result };
            }),
          );
          const nextResults = nextSettled.map((s, i) =>
            s.status === 'fulfilled'
              ? s.value
              : { name: nextCapped[i].functionCall!.name!, id: nextCapped[i].functionCall!.id, args: {}, result: { error: `Tool failed: ${(s.reason as Error)?.message ?? 'unknown'}` } },
          );

          // Add to raw data + trim for Gemini
          rawToolData.push(...nextResults.map((tr) => ({ tool: tr.name, args: tr.args, data: tr.result })));
          const nextTrimmed = nextResults.map((tr) => {
            const json = JSON.stringify(tr.result);
            if (json.length <= 4000) return tr;
            const trimmed: Record<string, unknown> = {};
            for (const [k, v] of Object.entries(tr.result)) {
              if (Array.isArray(v)) {
                trimmed[k] = v.slice(0, 5);
                if (v.length > 5) trimmed[`${k}_total`] = v.length;
              } else { trimmed[k] = v; }
            }
            return { ...tr, result: trimmed };
          });

          conversationParts = [
            ...conversationParts,
            { role: 'model', parts: followParts },
            { role: 'user', parts: nextTrimmed.map((tr) => ({
              functionResponse: { name: tr.name, id: tr.id, response: { output: tr.result } },
            })) },
          ];
        }

        // Fallback if Gemini still produced no text
        if (!finalText) {
          finalText = `Tools called: ${skillsUsed.join(', ')}. See the structured_data artifact for full results.`;
        }
      } else {
        finalText = geminiText(response) || 'No response generated.';
      }

      await recordRequest({
        ipHash, userQuery: userText, skillId: skillsUsed[0] ?? null,
        toolsCalled: skillsUsed, responseText: finalText.slice(0, 4000),
        tokensUsed: totalTokens, latencyMs: Date.now() - startMs, error: null,
      });

      const taskId = `task-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      const now = new Date().toISOString();

      // Build artifacts: always include summary; add structured data when tools were called
      const artifacts: Array<Record<string, unknown>> = [
        {
          artifactId: `${taskId}-summary`,
          name: 'summary',
          description: 'Human-readable response with markdown links',
          parts: [{ text: finalText }],
        },
      ];
      if (rawToolData.length > 0) {
        artifacts.push({
          artifactId: `${taskId}-data`,
          name: 'structured_data',
          description: 'Raw API results as structured JSON for downstream parsing',
          parts: [{ text: JSON.stringify(rawToolData) }],
        });
      }

      const resp = NextResponse.json({
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
      resp.headers.set('X-RateLimit-Limit', String(DAILY_LIMIT));
      resp.headers.set('X-RateLimit-Remaining', String(remaining));
      return withCors(resp);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      console.error('A2A error:', errMsg);
      await recordRequest({
        ipHash, userQuery: userText, skillId: null, toolsCalled: [],
        responseText: null, tokensUsed: 0, latencyMs: Date.now() - startMs, error: errMsg.slice(0, 1000),
      });
      return withCors(NextResponse.json(
        jsonRpcError(reqId, -32603, 'Internal error processing request'),
        { status: 500 },
      ));
    }
  } else {
    return withCors(NextResponse.json(
      jsonRpcError(reqId, -32601, 'Method not supported. Use SendMessage'),
      { status: 400 },
    ));
  }
}
