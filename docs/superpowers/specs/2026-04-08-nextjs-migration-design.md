# Next.js Full Migration Design

**Date:** 2026-04-08
**Status:** Revised — incorporates architect-reviewer, react-specialist, nextjs-developer findings

## Goal

Migrate MITRE Explorer Plus from Vite SPA + React Router v7 + standalone Vercel serverless to Next.js 15 App Router with full SSR/ISR for SEO, proper `<title>`/`<meta>` per page, and unified deployment.

**Primary driver:** Google Search Console shows "Page with redirect" for all pages — the SPA catch-all serves identical HTML for every URL. Google cannot index content.

## Scope

- Full Next.js App Router migration (not incremental)
- 73 API endpoints move to `app/api/`
- 36 pages move to `app/` with file-based routing
- React Router v7 fully removed (44 files import it, 14 use `useNavigate`, 19 use `setSearchParams`, 10 use `useParams`)
- SSR + ISR for high-value pages (techniques, groups, CVEs, all detail pages)
- Dynamic `generateMetadata()` for SEO
- Nonce-based CSP via middleware
- Theme flash prevention
- Sitemap + Open Graph tags
- A2A protocol preserved at `/api/a2a`

**Out of scope:** Database changes, new features, UI redesign.

---

## 1. Project Structure

```
mitre/
├── middleware.ts                  # CSP nonce injection (MUST be at root, not app/)
├── app/                          # Next.js App Router
│   ├── layout.tsx                # Root server layout (html, head, blocking theme script with nonce)
│   ├── providers.tsx             # 'use client' — Theme, Domain, Sector, QueryClient, Suspense
│   ├── not-found.tsx             # Custom 404 page
│   ├── error.tsx                 # Global error boundary ('use client')
│   ├── page.tsx                  # / → Relationships
│   ├── sitemap.ts                # Dynamic sitemap from DB
│   ├── robots.ts                 # Programmatic robots.txt
│   ├── api/                      # API routes (moved from /api)
│   │   ├── a2a/route.ts          # A2A protocol
│   │   ├── cron/                 # 9 cron handlers
│   │   └── v1/                   # 60+ REST endpoints
│   ├── relationships/page.tsx    # Redirect to / (preserves old /relationships URLs)
│   ├── dashboard/page.tsx
│   ├── matrix/page.tsx
│   ├── techniques/
│   │   ├── page.tsx              # SSR list
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── groups/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx
│   ├── campaigns/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── software/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── mitigations/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── tactics/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── data-sources/
│   │   ├── page.tsx
│   │   └── [attackId]/page.tsx   # ISR detail
│   ├── sectors/
│   │   ├── page.tsx
│   │   └── [sectorName]/page.tsx
│   ├── applications/page.tsx
│   ├── external-actors/page.tsx
│   ├── search/page.tsx
│   ├── cti/
│   │   ├── cves/
│   │   │   ├── page.tsx
│   │   │   └── [cveId]/page.tsx  # ISR detail
│   │   ├── reports/page.tsx
│   │   ├── iocs/page.tsx
│   │   ├── sigma/page.tsx
│   │   └── feed-status/page.tsx
│   └── frameworks/
│       ├── owasp/
│       │   ├── page.tsx          # List + accordion (shared component)
│       │   └── [categoryId]/page.tsx  # Same component, auto-expands category
│       ├── nist/page.tsx
│       ├── engage/page.tsx
│       ├── react/page.tsx
│       ├── veris/page.tsx
│       ├── cloud/page.tsx
│       ├── atomic/page.tsx
│       └── detection/page.tsx
├── src/                          # Shared code — unchanged
│   ├── components/               # All become 'use client'
│   ├── hooks/                    # useApi stays, usePageTitle deleted
│   ├── contexts/                 # Rewritten for next/navigation
│   └── lib/                      # Unchanged (client-only: apiFetch uses window.location)
├── public/                       # Static assets (includes .well-known/agent-card.json)
├── next.config.ts                # Replaces vite.config.ts
├── postcss.config.cjs            # Tailwind 4 via @tailwindcss/postcss
└── vercel.json                   # Crons + security headers only
```

### Key structural notes

- **`middleware.ts` at project root** — Next.js silently ignores it inside `app/`
- **`app/relationships/page.tsx`** — redirects to `/` to preserve existing `/relationships` links
- **`not-found.tsx` + `error.tsx`** — replace React Router `*` catch-all and `<ErrorBoundary>`
- **`public/.well-known/agent-card.json`** — served statically by Next.js, no API handler needed. Delete `api/agent-card.ts`
- **`server/dev-server.ts`** — deleted entirely, replaced by `next dev`

---

## 2. Page Rendering Strategy

### Server-side data fetching with `cache()`

All Tier 1 pages call data-fetch functions in both `generateMetadata` and `Page`. To avoid duplicate DB queries, wrap server-side fetch functions with React `cache()`:

```tsx
// app/lib/data.ts — server-side fetch utilities (NOT apiFetch which uses window.location)
import { cache } from 'react';
import { query } from '../api/v1/lib/db';

export const fetchTechnique = cache(async (attackId: string) => {
  const result = await query('SELECT ... FROM techniques WHERE attack_id = $1', [attackId]);
  return result.rows[0];
});

export const fetchGroup = cache(async (attackId: string) => { ... });
export const fetchCve = cache(async (cveId: string) => { ... });
// ... one per Tier 1 entity type
```

> **Why `cache()` not `apiFetch()`?** `src/lib/api.ts` uses `window.location.origin` — it crashes on the server. Server components must use direct DB queries or `process.env`-based absolute URLs.

### Next.js 15: `params` is a Promise

In Next.js 15 App Router, `params` and `searchParams` are **Promises**. All server components must `await` them:

```tsx
// app/techniques/[attackId]/page.tsx
import { fetchTechnique } from '../../lib/data';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);
  return {
    title: `${data.attackId} ${data.name} — MITRE Explorer`,
    description: data.description?.slice(0, 160),
    openGraph: { title: `${data.attackId} ${data.name}`, description: data.description?.slice(0, 160) },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);  // cache() deduplicates — same request as generateMetadata
  return <TechniqueDetailClient initialData={data} />;
}
```

### Hydrating React Query from SSR data

Tier 1 pages pass `initialData` as a prop. The client component uses it as React Query's `initialData` to avoid a second fetch:

```tsx
// src/components/TechniqueDetailClient.tsx
'use client';
export function TechniqueDetailClient({ initialData }: { initialData: Technique }) {
  const { data } = useTechnique(initialData.attackId, { initialData });
  // React Query skips the initial fetch, uses initialData, refetches on staleTime expiry
}
```

Alternative: use TanStack Query `HydrationBoundary` + `dehydrate`. The `initialData` prop approach is simpler for this codebase.

### Tier 1 — Full SSR + ISR (13 pages)

Server fetches data, passes as props, renders HTML for Google. Revalidates hourly.

Pages: `/techniques/[id]`, `/groups/[id]`, `/campaigns/[id]`, `/software/[id]`, `/mitigations/[id]`, `/tactics/[id]`, `/data-sources/[id]`, `/cti/cves/[id]`, `/frameworks/owasp/[id]`, `/sectors/[name]`, `/techniques` (list), `/groups` (list)

### Tier 2 — Static metadata + client render (20 pages)

Rich static descriptions, client-side data fetching via React Query.

| Page | Title | Description |
|------|-------|-------------|
| `/software` | `Attacker Software — MITRE Explorer` | `Malware and hacking tools used by threat actors mapped to ATT&CK techniques — from Cobalt Strike to Mimikatz` |
| `/campaigns` | `Campaigns — MITRE Explorer` | `Named intrusion operations with timelines, attributed groups, techniques, and software` |
| `/mitigations` | `Mitigations — MITRE Explorer` | `Security countermeasures mapped to ATT&CK techniques — access controls, network segmentation, endpoint protection` |
| `/tactics` | `Tactics — MITRE Explorer` | `Kill chain phases from Reconnaissance to Impact — each tactic groups the techniques adversaries use to achieve objectives` |
| `/sectors` | `Industry Sectors — MITRE Explorer` | `Threat landscape by industry — which groups, techniques, and campaigns target your sector` |
| `/applications` | `Applications — MITRE Explorer` | `7,000+ vendor products linked to CVEs, CWEs, and ATT&CK techniques — see what adversaries exploit in your stack` |
| `/matrix` | `ATT&CK Matrix — MITRE Explorer` | `Interactive technique heatmap across tactics — compare up to 3 threat actors, filter by domain and sector` |
| `/` | `360 Views — MITRE Explorer` | `Search any entity and explore its relationships — technique maps, actor profiles, application maps, and force-directed graphs` |
| `/frameworks/owasp` | `OWASP Top 10 — MITRE Explorer` | `Web (2021), ML (2023), and LLM (2025) security risks mapped to ATT&CK and ATLAS techniques via CWE` |
| `/frameworks/nist` | `NIST 800-53 Controls — MITRE Explorer` | `Federal security controls mapped to ATT&CK techniques for compliance assessment and gap analysis` |
| `/frameworks/engage` | `MITRE Engage — MITRE Explorer` | `Adversary deception and engagement activities mapped per ATT&CK technique` |
| `/frameworks/react` | `RE&CT Actions — MITRE Explorer` | `Incident response playbooks and actions mapped to ATT&CK techniques` |
| `/frameworks/veris` | `VERIS Categories — MITRE Explorer` | `Verizon DBIR incident classification mapped to ATT&CK techniques` |
| `/frameworks/cloud` | `Cloud Controls — MITRE Explorer` | `Azure and GCP security controls mapped to ATT&CK techniques` |
| `/frameworks/atomic` | `Atomic Tests — MITRE Explorer` | `Red team validation tests from Atomic Red Team mapped per ATT&CK technique` |
| `/frameworks/detection` | `Detection Strategies — MITRE Explorer` | `ATT&CK v18 detection strategies and analytics for SOC and threat hunting teams` |
| `/cti/cves` | `CVE Vulnerabilities — MITRE Explorer` | `21,000+ CVEs enriched with NVD scores, CISA KEV status, and ATT&CK technique mappings via CWE→CAPEC bridge` |
| `/data-sources` | `Data Sources — MITRE Explorer` | `Telemetry sources for detecting ATT&CK techniques — process monitoring, network traffic, logs` |
| `/external-actors` | `Non-MITRE Actors — MITRE Explorer` | `500+ extended threat actors from ThaiCERT/ETDA encyclopedia` |
| `/cti/reports` | `Threat Reports — MITRE Explorer` | `Live threat intelligence from AlienVault OTX and RSS feeds with ATT&CK technique extraction` |

> **Matrix moved to Tier 2** — it depends heavily on `useSearchParams` (actor comparison, domain/sector filters). SSR without those params produces an empty-ish view with low SEO value.

### Tier 3 — Minimal metadata, client only (5 pages)

| Page | Title | Description |
|------|-------|-------------|
| `/search` | `Search — MITRE Explorer` | `Search across techniques, groups, software, campaigns, CVEs, and OWASP categories` |
| `/cti/feed-status` | `Feed Status — MITRE Explorer` | `CTI pipeline health — ingestion status for OTX, NVD, CISA KEV, and threat feeds` |
| `/cti/iocs` | `IOC Indicators — MITRE Explorer` | `Hashes, domains, IPs from OTX, ThreatFox, and MalwareBazaar enriched with VirusTotal verdicts` |
| `/cti/sigma` | `Sigma Rules — MITRE Explorer` | `3,100+ detection signatures from SigmaHQ mapped to ATT&CK techniques for SOC analysts` |
| `/dashboard` | `Overview — MITRE Explorer` | `Summary statistics, top threat groups, technique distribution, and sector breakdown across the ATT&CK knowledge base` |

### OWASP page split strategy

Currently `OwaspTop10.tsx` is a single component handling both list and detail (accordion expand). After migration to two Next.js pages:

- **`app/frameworks/owasp/page.tsx`** — server metadata, renders `<OwaspTop10Client />` (no `categoryId` prop)
- **`app/frameworks/owasp/[categoryId]/page.tsx`** — server metadata with `generateMetadata` for the specific category, renders `<OwaspTop10Client initialCategoryId={categoryId} />`
- Both render the same client component; `initialCategoryId` prop controls which accordion is auto-expanded
- Client-side accordion clicks stay as state changes (no `router.push` needed)

---

## 3. API Migration

### Signature change (Next.js 15 async params)

```ts
// BEFORE — Vercel serverless
import type { VercelRequest, VercelResponse } from '@vercel/node';
async function handler(req: VercelRequest, res: VercelResponse) {
  const q = req.query.q as string;
  res.setHeader('Cache-Control', '...');
  res.status(200).json({ data });
}
export default withHandler(handler, { cacheTtl: 3600 });

// AFTER — Next.js 15 Route Handler (params is a Promise)
import { NextRequest, NextResponse } from 'next/server';
export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ attackId: string }> }
) {
  const { attackId } = await params;
  const q = req.nextUrl.searchParams.get('q');
  const data = await query(...);
  return NextResponse.json({ data }, {
    headers: { 'Cache-Control': 'public, s-maxage=3600, stale-while-revalidate=86400' },
  });
}
```

### Middleware rewrite

`withHandler` becomes a shared utility:

```ts
// app/api/lib/handler.ts
import { NextResponse } from 'next/server';

export function jsonResponse(data: unknown, cacheTtl?: number) {
  const headers: Record<string, string> = {};
  if (cacheTtl) headers['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  return NextResponse.json(data, { headers });
}

export function errorResponse(status: number, error: string, code: string) {
  return NextResponse.json({ error, code }, { status });
}
```

### CORS handling

The CSP middleware matcher excludes `/api` routes (intentional — API routes don't need nonces). CORS must be handled separately:

```ts
// app/api/lib/cors.ts
import { NextRequest, NextResponse } from 'next/server';

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

export function corsOptions() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

export function withCors(response: NextResponse) {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => response.headers.set(k, v));
  return response;
}
```

Each API route that needs CORS exports an `OPTIONS` handler:

```ts
export { corsOptions as OPTIONS } from '../lib/cors';
export async function GET(req: NextRequest) {
  const data = await query(...);
  return withCors(NextResponse.json(data));
}
```

### A2A protocol

- `api/a2a/index.ts` → `app/api/a2a/route.ts`
- `export const config = { api: { bodyParser: ... } }` → removed; use `req.json()` directly
- `export default handler` → `export async function POST(req: NextRequest)` + `export { corsOptions as OPTIONS }`
- Rate limiting logic unchanged
- Google GenAI SDK unchanged
- `callInternalApi()` — update to use `process.env.NEXT_PUBLIC_SITE_URL || 'http://localhost:3000'` instead of hardcoded domain. Preview deployments get `VERCEL_URL` automatically.

### Cron jobs

- `api/cron/*.ts` → `app/api/cron/*/route.ts`
- **Export `GET` not `POST`** — Vercel crons send GET requests by default
- Cron secret validation unchanged (`req.headers.get('x-vercel-cron-secret')`)
- `vercel.json` cron paths stay the same (`/api/cron/*`)
- Carry over `maxDuration` per route: `export const maxDuration = 300;`

### Shared libs

- `api/v1/lib/db.ts` → `app/api/v1/lib/db.ts` — unchanged
- `api/v1/lib/validate.ts` → `app/api/v1/lib/validate.ts` — unchanged
- `api/v1/lib/middleware.ts` → rewritten as `app/api/lib/handler.ts` + `app/api/lib/cors.ts`

### agent-card.ts

**Delete `api/agent-card.ts`** — `public/.well-known/agent-card.json` is served statically by Next.js at `/.well-known/agent-card.json`. If custom headers (CORS, cache-control) are needed, add them via `next.config.ts` `headers()`.

---

## 4. React Router Removal

### Exact counts (from codebase grep)

| Import | Count | Files |
|---|---|---|
| `react-router-dom` total | 44 files | All pages, contexts, some components |
| `useNavigate()` | 14 files | List pages, Search, SearchBar, Dashboard, RelationshipModel |
| `setSearchParams` | 19 files | 2 contexts + 17 pages (see full list below) |
| `useParams()` | 10 files | All detail pages + OwaspTop10 |
| `NavLink` | 1 file | Sidebar.tsx |
| `Link` | ~20 files | Various |

### Replacement map

| React Router | Next.js | Files |
|---|---|---|
| `Link` from `react-router-dom` | `Link` from `next/link` (`to` → `href`) | ~20 |
| `useNavigate()` | `useRouter().push()` from `next/navigation` | 14 files |
| `useParams()` | Props from server `page.tsx` or `useParams()` from `next/navigation` | 10 files |
| `useSearchParams()` | `useSearchParams()` from `next/navigation` (read-only) | 19 files |
| `setSearchParams(fn)` | `router.push()` with manual URL construction (see below) | 19 files |
| `NavLink` with `isActive` | Custom using `usePathname()` | Sidebar.tsx |
| `useLocation()` | `usePathname()` | Sidebar.tsx, contexts |
| `BrowserRouter` | Removed | main.tsx deleted |
| `Routes`, `Route`, `Outlet` | Removed — file-based routing | App.tsx deleted |
| `React.lazy()` | Removed — automatic code splitting | App.tsx deleted |

### `setSearchParams` migration — all 19 files

React Router's `setSearchParams` accepts a functional updater `(prev) => next`. Next.js has no equivalent — `useSearchParams()` is read-only. Each site must be rewritten:

```tsx
// BEFORE (React Router)
const [searchParams, setSearchParams] = useSearchParams();
setSearchParams((prev) => {
  const next = new URLSearchParams(prev);
  next.set('page', String(page));
  return next;
});

// AFTER (Next.js)
const searchParams = useSearchParams();
const router = useRouter();
const pathname = usePathname();

function updateParams(updates: Record<string, string | null>) {
  const params = new URLSearchParams(searchParams.toString());
  Object.entries(updates).forEach(([k, v]) => {
    if (v === null) params.delete(k);
    else params.set(k, v);
  });
  router.push(`${pathname}?${params.toString()}`);
}
```

**Full list of files requiring this rewrite:**
Contexts (2): `DomainContext.tsx`, `SectorContext.tsx`
Pages (17): `Relationships.tsx`, `Search.tsx`, `CvesList.tsx`, `IocsList.tsx`, `ApplicationsList.tsx`, `TechniquesList.tsx`, `DetectionStrategies.tsx`, `ReportsList.tsx`, `SigmaList.tsx`, `AtomicTests.tsx`, `SoftwareList.tsx`, `ReactActions.tsx`, `NistControls.tsx`, `MitigationsList.tsx`, `GroupsList.tsx`, `ExternalActors.tsx`, `EngageActivities.tsx`

> **`DataSourcesList.tsx` and `CampaignsList.tsx`** also in the grep results — verify if they use the setter or just the reader.

### Suspense boundaries for `useSearchParams`

Any component calling `useSearchParams()` from `next/navigation` must be wrapped in `<Suspense>` or the entire page opts out of static rendering. Strategy:

1. **`providers.tsx`** — wraps `DomainProvider` + `SectorProvider` in a shared `<Suspense>` (these call `useSearchParams` internally)
2. **Sidebar** — must be a child of `providers.tsx`, not a sibling (it consumes Domain/Sector contexts which depend on `useSearchParams`)
3. **Per-page `useSearchParams`** — each of the 17 page components that directly calls `useSearchParams` needs a `<Suspense>` boundary at the page level:

```tsx
// app/cti/cves/page.tsx
import { Suspense } from 'react';
import { CvesListClient } from '@/src/pages/CvesList';
import { DiamondLoader } from '@/src/components/shared/FoldingDiamond';

export const metadata = { title: 'CVE Vulnerabilities — MITRE Explorer', ... };
export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <CvesListClient />
    </Suspense>
  );
}
```

### Context rewrites

**DomainContext + SectorContext race condition:** Both contexts have `useEffect` hooks that re-inject their stored value into the URL on mount. With React Router's `setSearchParams(fn)`, these merged safely. With Next.js `router.push()`, two sequential pushes overwrite each other (second push drops first's param).

**Fix:** Merge both context's URL-sync effects into a single coordinated effect in `providers.tsx`:

```tsx
// app/providers.tsx — merged URL sync
useEffect(() => {
  const params = new URLSearchParams(searchParams.toString());
  let changed = false;
  if (storedDomain && !params.has('domain')) { params.set('domain', storedDomain); changed = true; }
  if (storedSector && !params.has('sector')) { params.set('sector', storedSector); changed = true; }
  if (changed) router.replace(`${pathname}?${params.toString()}`);
}, []); // once on mount
```

### Layout component migration

The current `App.tsx` `Layout` component contains: sidebar toggle state, about modal, VtBadge, header chrome, error boundary wrapping, and the `<Outlet />` slot. This becomes:

- **`app/layout.tsx`** — server component: `<html>`, `<head>`, blocking theme script, wraps `<Providers>{children}</Providers>`
- **`app/providers.tsx`** — `'use client'`: Theme, Domain, Sector, QueryClient, merged URL sync, `<Suspense>`, `<Analytics />`
- **`src/components/layout/AppShell.tsx`** — `'use client'`: new component extracted from `Layout` in `App.tsx`. Contains sidebar, header, about modal, VtBadge. Renders `{children}` where `<Outlet />` was.

```tsx
// app/layout.tsx (server)
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head><script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} /></head>
      <body>
        <Providers>
          <AppShell>{children}</AppShell>
        </Providers>
      </body>
    </html>
  );
}
```

### Sidebar NavLink replacement

```tsx
const pathname = usePathname();
const isActive = pathname === path || pathname.startsWith(path + '/');
```

### Sidebar `window.innerWidth` hydration fix

`CollapsibleNavSection` reads `window.innerWidth` in `useState` initializer — this is `undefined` during SSR, causing hydration mismatch on mobile. Fix:

```tsx
// Initialize with desktop default, sync on mount
const [open, setOpen] = useState(defaultOpen || isActiveRoute);
useEffect(() => {
  if (window.innerWidth < 1024 && !isActiveRoute) setOpen(false);
}, []);
```

### Files deleted

- `src/App.tsx` — routing moves to file system, Layout → AppShell
- `src/main.tsx` — replaced by `app/layout.tsx`
- `src/hooks/usePageTitle.ts` — replaced by `generateMetadata`
- `vite.config.ts` — replaced by `next.config.ts`
- `index.html` — replaced by `app/layout.tsx`
- `server/dev-server.ts` — replaced by `next dev`
- `api/agent-card.ts` — served statically from `public/`

---

## 5. Theme, CSP, and Build Config

### Theme flash prevention

Blocking inline script in `app/layout.tsx` `<head>`. Uses `localStorage.getItem('theme')` (**must match ThemeContext key**, which is `'theme'`):

```tsx
// app/layout.tsx
import { headers } from 'next/headers';

const THEME_SCRIPT = `(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme:dark)').matches)) {
      document.documentElement.classList.add('dark');
    }
  } catch(e) {}
})();`;

export default async function RootLayout({ children }) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') ?? '';

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
```

### ThemeContext hydration

`getInitialTheme()` reads `localStorage` synchronously in `useState`. On SSR it returns `'light'`, but the blocking script may have added class `dark`. To avoid hydration mismatch, add `suppressHydrationWarning` on `<html>` (shown above) and initialize theme state lazily:

```tsx
const [theme, setTheme] = useState<Theme>('light');
useEffect(() => {
  const stored = localStorage.getItem('theme') as Theme | null;
  if (stored === 'dark' || stored === 'light') setTheme(stored);
  else if (window.matchMedia('(prefers-color-scheme: dark)').matches) setTheme('dark');
}, []);
```

### CSP nonce via middleware

**`middleware.ts` at project root** (NOT inside `app/`):

```ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = crypto.randomUUID();
  const csp = [
    `default-src 'self'`,
    `script-src 'self' 'nonce-${nonce}' https://va.vercel-scripts.com`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data: blob:`,
    `connect-src 'self' https://*.vercel-insights.com`,
  ].join('; ');

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('x-nonce', nonce);
  return response;
}

// Exclude API routes (they don't need nonces) and static assets
export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon).*)'],
};
```

> **CORS for API routes** is handled via `app/api/lib/cors.ts` (see Section 3), not this middleware.

### `providers.tsx` — QueryClient instantiation

**Critical:** `QueryClient` must be created inside a component via `useState`, not at module scope. Module-scope instances are shared across SSR requests, leaking data between users:

```tsx
'use client';
import { useState } from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: { queries: { staleTime: 2 * 60 * 1000 } },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <Suspense fallback={<DiamondLoader text="Loading..." />}>
          <DomainProvider>
            <SectorProvider>
              <AppShell>{children}</AppShell>
            </SectorProvider>
          </DomainProvider>
        </Suspense>
      </ThemeProvider>
      <Analytics />
    </QueryClientProvider>
  );
}
```

> **`<Analytics />`** from `@vercel/analytics/react` moves here from the deleted `App.tsx`.

### vercel.json (slimmed)

Keeps: crons (9 jobs), security headers (HSTS, X-Frame-Options, etc.)
Removes: `framework`, `buildCommand`, `outputDirectory`, `rewrites`, CSP header

### next.config.ts

```ts
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['d3', 'd3-force', 'd3-selection', 'fuse.js'],
  // No dev rewrites — API routes live in app/api/, served by next dev
};

export default nextConfig;
```

> **Dev rewrite to localhost:3001 removed** — the old Express dev server (`server/dev-server.ts`) is deleted. `next dev` serves both pages and API routes.

### postcss.config.cjs

```js
module.exports = { plugins: { '@tailwindcss/postcss': {} } };
```

> Uses `.cjs` extension because `package.json` has `"type": "module"` which conflicts with PostCSS's CommonJS requirement.

### tsconfig.json changes

- Remove `"types": ["vite/client"]`
- Add `"plugins": [{ "name": "next" }]`
- Add `"app/**/*.ts"` and `"app/**/*.tsx"` to `include` array
- Keep `"moduleResolution": "bundler"`

### package.json scripts

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "postinstall": "..."
  }
}
```

Remove: `dev:frontend`, `dev:api`, `build:frontend`, `preview`, and any `vite` or `tsx watch server/dev-server.ts` scripts.

### D3 and recharts — SSR-unsafe components

Wrap D3 and recharts components with `next/dynamic({ ssr: false })`:

```tsx
import dynamic from 'next/dynamic';
const ForceGraph = dynamic(() => import('@/src/components/graph/ForceGraph'), { ssr: false });
const GroupTechniqueChart = dynamic(() => import('@/src/components/GroupTechniqueChart'), { ssr: false });
```

> `recharts` (`ResponsiveContainer`) and `dompurify` also require `window` — only used in `'use client'` components, but wrapping with `ssr: false` prevents hydration mismatches.

### Performance: `next/link` prefetching

On high-link-density pages (Matrix grid, technique lists), disable automatic prefetch to avoid hammering the API:

```tsx
<Link href={`/techniques/${t.attackId}`} prefetch={false}>
```

---

## 6. SEO Additions

### Dynamic sitemap (`app/sitemap.ts`)

Generates sitemap from DB — all techniques, groups, CVEs, OWASP categories:

```ts
export default async function sitemap() {
  const techniques = await query('SELECT attack_id FROM techniques WHERE ...');
  const groups = await query('SELECT attack_id FROM threat_groups WHERE ...');
  // ... build URL entries with lastModified dates
  return [...staticPages, ...techniqueUrls, ...groupUrls, ...cveUrls];
}
```

### Programmatic robots.txt (`app/robots.ts`)

```ts
export default function robots() {
  return {
    rules: { userAgent: '*', allow: '/', disallow: ['/api/', '/search'] },
    sitemap: 'https://mitre-explorer.org/sitemap.xml',
  };
}
```

### Open Graph tags

Added via `generateMetadata()` — `openGraph.title`, `openGraph.description`, `openGraph.url` per page.

---

## 7. Migration Phases

### Phase 0: Scaffold + Spike (1 session)

- Install `next`, `@tailwindcss/postcss`; remove `vite`, `@tailwindcss/vite`
- Create `next.config.ts`, `postcss.config.cjs`, update `tsconfig.json`
- Update `package.json` scripts (`next dev`, `next build`, `next start`)
- Create `middleware.ts` at project root for CSP nonces
- Create `app/layout.tsx` with blocking theme script (nonce-aware)
- Create `app/providers.tsx` with all contexts + QueryClient (`useState`) + Suspense + Analytics
- Create `app/not-found.tsx` and `app/error.tsx`
- Create `app/lib/data.ts` with `cache()`-wrapped server fetch functions
- Create `app/sitemap.ts` and `app/robots.ts` (proof-of-value for SEO)
- Migrate 1 API endpoint (`dashboard`) to `app/api/v1/dashboard/route.ts`
- Migrate 1 page (`dashboard`) with `generateMetadata`
- Run bundle analysis baseline (compare with current Vite build)
- Deploy preview branch — verify against acceptance criteria
- **Gate — all must pass:**
  - `curl` shows SSR HTML with `<title>` and `<meta>` tags
  - CSP nonce applied — no console errors for blocked scripts
  - Theme does not flash on dark-mode load
  - API route returns correct data
  - A2A endpoint responds on preview URL
  - sitemap.xml returns valid XML

### Phase 1: API Layer (1-2 sessions)

- Create `app/api/lib/handler.ts` (jsonResponse, errorResponse) and `app/api/lib/cors.ts`
- Move all 73 endpoints to `app/api/` with signature changes (async params, GET/POST exports)
- Migrate A2A to `app/api/a2a/route.ts` (POST + OPTIONS)
- Migrate cron handlers (export GET, add `maxDuration`)
- Move shared libs (`db.ts`, `validate.ts`)
- Delete `api/agent-card.ts`
- Verify every endpoint
- **Rollback:** old `api/` directory kept on a `pre-migration` tag; can be restored by reverting the commit

### Phase 2a: Contexts + Layout + Sidebar (1 session)

Highest risk, most complex. Do this before pages.

- Rewrite `DomainContext` + `SectorContext` for `next/navigation` (`useSearchParams` read-only)
- Implement merged URL-sync effect in `providers.tsx` (prevents race condition)
- Extract `AppShell` from `App.tsx` `Layout` (sidebar, header, modals, VtBadge)
- Rewrite `Sidebar.tsx` — replace `NavLink` with `usePathname()`, fix `window.innerWidth` hydration
- Wrap D3/recharts components with `next/dynamic({ ssr: false })` early to prevent SSR crashes
- Remove `usePageTitle` hook (37 files) — replaced by `generateMetadata`

### Phase 2b: Tier 1 SSR pages (1 session)

- Create `app/lib/data.ts` server fetch functions (if not done in Phase 0)
- Migrate 13 Tier 1 pages: server `page.tsx` with `generateMetadata` + `revalidate` + client wrapper with `initialData` prop
- Replace all React Router imports in these files

### Phase 2c: Tier 2 + Tier 3 pages (1-2 sessions)

- Migrate 25 remaining pages — static metadata in server page, `'use client'` component
- Rewrite `setSearchParams` in all 17 page files (mechanical — use `updateParams` helper)
- Add per-page `<Suspense>` boundaries for pages using `useSearchParams`
- Create `app/relationships/page.tsx` with redirect to `/`
- Create OWASP split pages (`page.tsx` + `[categoryId]/page.tsx`, shared client component)
- Replace all remaining React Router imports across components
- Add `prefetch={false}` on high-density link pages

### Phase 3: Cleanup + Verification (1 session)

- Delete `src/App.tsx`, `src/main.tsx`, `src/hooks/usePageTitle.ts`, `index.html`, `vite.config.ts`, `server/dev-server.ts`, old `api/` directory
- Bundle analysis — compare with Phase 0 baseline
- Final deploy + Google Search Console verification
- Submit sitemap to Google
- Verify all 44 react-router-dom imports are gone (`grep` should return 0)

**Total: 6-8 sessions**

### Rollback strategy

Each phase is a separate branch/PR. If a phase breaks production:
- **Phase 0-1:** Revert to `pre-migration` git tag (old `api/` + Vite still intact)
- **Phase 2a-c:** Vercel instant rollback to previous deployment
- **Phase 3:** Only cleanup — no new functionality, safe to revert individual commits

---

## Lessons Learned (from reviews)

1. **`middleware.ts` must be at project root** — `app/middleware.ts` is silently ignored by Next.js
2. **Next.js 15 `params` is a Promise** — `const { id } = await params` everywhere
3. **`generateMetadata` + `Page` double-fetch** — wrap server fetch in `cache()` from React
4. **CSP nonce must reach the `<script>` tag** — read from `headers()` in layout, pass as `nonce` attr
5. **Theme `localStorage` key must match** — blocking script and ThemeContext both use `'theme'`
6. **`setSearchParams` doesn't exist in Next.js** — 19 files need manual rewrite to `router.push()`
7. **Two contexts pushing URL params = race condition** — merge into single coordinated effect
8. **`QueryClient` must be in `useState`** — module-scope instance leaks data across SSR requests
9. **`useSearchParams` consumers need `<Suspense>`** — both context-level and per-page
10. **CORS: middleware matcher excludes `/api`** — handle via per-route `OPTIONS` export + `withCors` wrapper
11. **`api/` cannot coexist with `app/` as standalone Vercel serverless when framework=nextjs** — must move to `app/api/`
12. **`DomainContext`/`SectorContext` use `setSearchParams` functional updater** — full rewrite needed
13. **CSP hardcoded SHA breaks per deploy** — nonce-based via middleware required
14. **Theme flash guaranteed without blocking inline script in `<head>`**
15. **`usePageTitle` conflicts with `generateMetadata`** — remove entirely (37 files)
16. **D3 + recharts + dompurify need `{ ssr: false }`** — direct DOM manipulation crashes SSR
17. **`NavLink` has no Next.js equivalent** — reimplement with `usePathname()`
18. **`package.json` `"type": "module"` conflicts with PostCSS** — use `.cjs` extension
19. **Sidebar `window.innerWidth` in `useState` initializer** — SSR hydration mismatch, initialize with default then sync in `useEffect`
20. **`apiFetch` uses `window.location.origin`** — server-side pages need separate `app/lib/data.ts` with direct DB queries
21. **Vercel crons send GET requests** — export `GET`, not `POST`
22. **`callInternalApi()` in A2A uses hardcoded domain** — use `process.env.NEXT_PUBLIC_SITE_URL` or `VERCEL_URL`
23. **Layout component is the most complex migration piece** — extract as `AppShell` client component early
