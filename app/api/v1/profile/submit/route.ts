import { NextRequest, NextResponse } from 'next/server';
import { createHash, createHmac } from 'node:crypto';
import { query } from '../../lib/db';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCorsRestricted, corsOptionsRestricted } from '../../../lib/cors';
import { submissionSchema } from '../../../../../src/lib/profile-submit-schema.mjs';

// Restricted CORS: this is the repo's first unauthenticated public WRITE. The
// open default (app/api/lib/cors.ts:5-9, `Access-Control-Allow-Origin: *` with
// POST) would let any cross-origin page silently burn the per-visitor daily
// cap below on a victim's behalf. Same rationale as A2A (app/api/a2a/route.ts:7-8).
export async function OPTIONS(req: NextRequest) { return corsOptionsRestricted(req); }

/**
 * Threat Profile telemetry sink. Anonymous by construction (see
 * scripts/migrate-profile-submissions.sql): no raw IP, UA, referrer, cookie,
 * or session is ever persisted -- only a per-day-rotating pseudonymous hash.
 *
 * This endpoint produces the single metric the whole Threat Profile feature
 * is judged on (the apply/dismiss ratio), so it ships one phase before the UI
 * that calls it, deliberately, and is validated + rate-limited up front.
 */

// 2 variants x 3 actions = 6 legitimate rows/day/visitor (the UNIQUE
// constraint on profile_submissions caps duplicates of the same combo to 1
// row regardless of how many times it's POSTed). 20 gives headroom for
// retries and multi-session use in a day without letting a script hammer
// the table indefinitely.
const DAILY_LIMIT = 20;

// -- Visitor pseudonymization -------------------------------------------------

/**
 * Static salt used to derive the daily HMAC key below. Module state is
 * per-lambda-instance and no timer runs in a frozen serverless function, so
 * an in-memory rotating salt (this endpoint's earlier draft) rotates on cold
 * start and hashes the same visitor differently per instance -- it never
 * delivers the intended daily rotation. A static env var plus a daily HMAC
 * does: the HMAC key changes once per UTC calendar day, deterministically,
 * no matter which lambda instance computes it.
 *
 * Set PROFILE_IP_SALT in the Vercel environment.
 *
 * Resolved PER REQUEST, and never at module scope.
 *
 * This used to be a module-level IIFE that threw when the var was missing in
 * production. `next build` imports every route to collect page data with
 * NODE_ENV=production, so that threw during the BUILD: a missing runtime
 * secret took down the whole deployment rather than the one endpoint that
 * needs it. Every preview build failed on it — the var is scoped to
 * Production — which meant each Renovate dependency PR came back red for a
 * reason that had nothing to do with the dependency.
 *
 * The security posture is unchanged and still deliberate: production never
 * hashes with the dev fallback. It now REFUSES THE REQUEST instead of
 * refusing to build, which is the correct blast radius for a config problem.
 * Local dev and test keep the warn-and-fallback so `npm test` and
 * `npm run dev` need nothing extra.
 *
 * Returns null when production has no salt; the caller turns that into a 503.
 */
function resolveIpSalt(): string | null {
  const salt = process.env.PROFILE_IP_SALT;
  if (salt) return salt;
  if (process.env.NODE_ENV === 'production') return null;
  console.warn('[profile/submit] PROFILE_IP_SALT is not set — using insecure fallback. Set the env var in production.');
  return 'dev-only-insecure-salt';
}

function getRawClientIp(req: NextRequest): string {
  // Trust only infrastructure-set headers — never the user-supplied
  // `x-forwarded-for` (an attacker can spoof it to rotate through "fresh"
  // IPs and bypass the per-visitor daily cap).
  //
  // Header precedence, same as app/api/a2a/route.ts — see the long note there
  // for why `cf-connecting-ip` is LAST and conditional. Short version: it was
  // first and unconditional, justified by Cloudflare overwriting a
  // client-supplied value, but this deployment is not behind Cloudflare
  // (`server: Vercel`, no `cf-ray`), so the header arrived caller-controlled
  // and rotating it reset the per-visitor daily cap.
  //   1. `x-vercel-forwarded-for` — set by the Vercel edge; client cannot choose it.
  //   2. `x-real-ip` — legacy Vercel, same guarantee.
  //   3. `cf-connecting-ip` — only when `cf-ray` proves Cloudflare is in front.
  const vercelIp = req.headers.get('x-vercel-forwarded-for');
  if (vercelIp) return vercelIp.split(',')[0].trim();
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  const cfIp = req.headers.get('cf-connecting-ip');
  if (cfIp && req.headers.get('cf-ray')) return cfIp.trim();
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
 * ip_day    = sha256(hmac(PROFILE_IP_SALT, utc_date) || ip)              -- IP only
 * visitor_day = sha256(hmac(PROFILE_IP_SALT, utc_date) || ip || ua)      -- IP + UA
 *
 * The HMAC keys on the UTC calendar day, so both digests -- and therefore
 * every downstream hash -- rotate at UTC midnight without any in-process
 * timer or stored rotation state. ip/ua are never stored raw, only folded
 * into these one-way hashes.
 *
 * Fix round 1 (Critical): `ip_day` is the one that gates the rate limiter.
 * `visitor_day` folds in the User-Agent header, which is fully
 * attacker-controlled -- using it for the cap meant varying UA per request
 * from a single IP minted a "new visitor" (count 0) every time, proven live
 * to bypass the cap entirely (15/15 requests succeeded, 15 distinct
 * visitor_day values, 1 constant IP). `visitor_day` is kept for storage
 * grouping and the UNIQUE dedup below -- UA still buys real visitor
 * separation behind shared NAT for THAT purpose -- but it must never again
 * be load-bearing for abuse resistance.
 */
function computeVisitorHashes(req: NextRequest, salt: string): { ipDay: string; visitorDay: string } {
  const utcDate = new Date().toISOString().slice(0, 10); // YYYY-MM-DD, UTC
  const dayKey = createHmac('sha256', salt).update(utcDate).digest('hex');
  const ip = getRawClientIp(req);
  const ua = req.headers.get('user-agent') ?? 'unknown';
  const ipDay = createHash('sha256').update(dayKey).update(ip).digest('hex');
  const visitorDay = createHash('sha256').update(dayKey).update(ip).update(ua).digest('hex');
  return { ipDay, visitorDay };
}

// -- Rate limiting -------------------------------------------------------------

/**
 * Per-IP daily cap, scoped to the same UTC calendar day the `day` column and
 * ip_day hash both use. Mirrors checkRateLimit in app/api/a2a/route.ts:214-221
 * (IP-hash only, no UA) -- the same shape the design spec specifies and the
 * one place this must never drift from again. The caller below fails CLOSED
 * on any error.
 */
async function underDailyCap(ipDay: string): Promise<boolean> {
  const result = await query<{ count: string }>(
    `SELECT COUNT(*) FROM profile_submissions
     WHERE ip_day = $1 AND day = (now() AT TIME ZONE 'utc')::date`,
    [ipDay],
  );
  const used = parseInt(result.rows[0].count, 10);
  return used < DAILY_LIMIT;
}

// -- Route ---------------------------------------------------------------------

export async function POST(req: NextRequest): Promise<NextResponse> {
  const withCors = (resp: NextResponse) => withCorsRestricted(resp, req);

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return withCors(errorResponse(400, 'Invalid JSON body', 'VALIDATION_ERROR'));
  }

  const parsed = submissionSchema.safeParse(body);
  if (!parsed.success) {
    return withCors(errorResponse(400, 'Invalid submission payload', 'VALIDATION_ERROR'));
  }

  /* Config problem, not a caller problem: 503 rather than 4xx, and the write
     is refused rather than hashed with the dev fallback. Logged so it is
     visible in the function logs instead of only in a missing metric. */
  const salt = resolveIpSalt();
  if (!salt) {
    console.error('[profile/submit] PROFILE_IP_SALT is not set in production — refusing to record.');
    return withCors(errorResponse(503, 'Telemetry is unavailable', 'CONFIG_ERROR'));
  }

  const { ipDay, visitorDay } = computeVisitorHashes(req, salt);

  // Fail CLOSED: an error while checking the cap rejects the write rather
  // than silently allowing it — same posture as a2a/route.ts:295-318.
  try {
    if (!(await underDailyCap(ipDay))) {
      const resp = NextResponse.json({ error: 'Rate limit exceeded', code: 'RATE_LIMITED' }, { status: 429 });
      resp.headers.set('Retry-After', '86400');
      return withCors(resp);
    }
  } catch (err) {
    console.error('profile/submit rate limit check failed:', err instanceof Error ? err.message : err);
    return withCors(errorResponse(503, 'Service temporarily unavailable', 'INTERNAL_ERROR'));
  }

  const { variant, action, sectors, platforms, roles, frameworks, assets, purdue_levels } = parsed.data;

  try {
    // ON CONFLICT DO NOTHING against the UNIQUE (day, visitor_day, action,
    // variant) constraint — one apply and one dismiss (and one auto_close)
    // per visitor-day-variant; a resubmission is a silent no-op, not an error.
    // ip_day rides along purely so the next request's rate-limit check can
    // find this row -- it plays no role in the uniqueness/dedup logic.
    await query(
      `INSERT INTO profile_submissions
         (variant, action, sectors, platforms, roles, frameworks, assets, purdue_levels, visitor_day, ip_day)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT DO NOTHING`,
      [variant, action, sectors, platforms, roles, frameworks, assets, purdue_levels, visitorDay, ipDay],
    );
  } catch (err) {
    console.error('profile/submit insert failed:', err instanceof Error ? err.message : err);
    return withCors(errorResponse(500, 'Internal server error', 'INTERNAL_ERROR'));
  }

  // jsonResponse() (not a raw NextResponse.json) so this success path is
  // counted in api_usage under the correct normalized endpoint -- the reason
  // middleware.ts STATIC_CHILDREN needed a `profile: new Set(['submit'])`
  // entry (task 7). No cacheTtl: this is a write, never CDN-cacheable.
  return withCors(jsonResponse({ ok: true }));
}
