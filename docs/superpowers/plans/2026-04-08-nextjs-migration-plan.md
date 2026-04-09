# Next.js Full Migration — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate MITRE Explorer Plus from Vite SPA + React Router v7 + standalone Vercel serverless to Next.js 15 App Router with SSR/ISR for SEO.

**Architecture:** File-based routing via `app/` directory. Server components for metadata + data fetching (Tier 1 pages), `'use client'` wrappers for interactive components. CSP nonce via root `middleware.ts`. React Query stays for client-side caching; SSR pages pass `initialData` props. 73 API routes move to `app/api/` route handlers.

**Tech Stack:** Next.js 15, React 19, TypeScript, TanStack React Query, Tailwind CSS 4 (via `@tailwindcss/postcss`), PostgreSQL (pg), D3.js, recharts, Vercel deployment.

**Spec:** `docs/superpowers/specs/2026-04-08-nextjs-migration-design.md`

---

## Chunk 1: Phase 0 — Scaffold + Spike

### Task 1: Install Next.js, remove Vite

**Files:**
- Modify: `package.json`
- Delete: `vite.config.ts`
- Create: `next.config.ts`
- Create: `postcss.config.cjs`
- Modify: `tsconfig.json`

- [ ] **Step 1: Install Next.js and PostCSS plugin**

```bash
npm install next @tailwindcss/postcss
npm uninstall @vitejs/plugin-react @tailwindcss/vite vite
```

- [ ] **Step 2: Create `next.config.ts`**

```ts
// next.config.ts
import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['d3', 'd3-force', 'd3-selection', 'fuse.js'],
};

export default nextConfig;
```

- [ ] **Step 3: Create `postcss.config.cjs`**

```js
// postcss.config.cjs
module.exports = { plugins: { '@tailwindcss/postcss': {} } };
```

- [ ] **Step 4: Update `tsconfig.json`**

Remove `"types": ["vite/client"]`, add Next.js plugin and `app/` includes. **`middleware.ts` must be in `include`** since it's at the project root:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "bundler",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "outDir": "dist",
    "rootDir": ".",
    "baseUrl": ".",
    "resolveJsonModule": true,
    "declaration": false,
    "sourceMap": false,
    "forceConsistentCasingInFileNames": true,
    "jsx": "react-jsx",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "plugins": [{ "name": "next" }]
  },
  "include": ["middleware.ts", "app/**/*.ts", "app/**/*.tsx", "api/**/*.ts", "server/**/*.ts", "src/**/*.ts", "src/**/*.tsx", "next-env.d.ts"],
  "exclude": ["node_modules", "dist", "venv", ".next"]
}
```

- [ ] **Step 5: Update `package.json` scripts**

Replace the `scripts` section:

```json
{
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint",
    "typecheck": "tsc --noEmit",
    "seed": "./venv/bin/python seed/seed.py",
    "seed:prod": "DATABASE_URL=$POSTGRES_URL ./venv/bin/python seed/seed.py --confirm-destructive",
    "seed:update": "./venv/bin/python seed/seed.py --update",
    "seed:verify": "./venv/bin/python seed/verify.py",
    "test": "echo \"Error: no test specified\" && exit 1"
  }
}
```

- [ ] **Step 6: Tag current state for rollback**

```bash
git tag pre-migration
```

- [ ] **Step 7: Delete `vite.config.ts`**

```bash
rm vite.config.ts
```

- [ ] **Step 8: Commit**

```bash
git add package.json tsconfig.json next.config.ts postcss.config.cjs
git add -u  # catches vite.config.ts deletion
git commit -m "chore: swap vite for next.js 15, update tsconfig and scripts"
```

---

### Task 2: Create CSP nonce middleware

**Files:**
- Create: `middleware.ts` (project root — NOT inside `app/`)

- [ ] **Step 1: Create `middleware.ts`**

```ts
// middleware.ts — MUST be at project root
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export function middleware(request: NextRequest) {
  const nonce = crypto.randomUUID();
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' https://va.vercel-scripts.com`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "connect-src 'self' https://*.vercel-insights.com https://va.vercel-scripts.com https://vitals.vercel-insights.com",
    "font-src 'self'",
  ].join('; ');

  const response = NextResponse.next();
  response.headers.set('Content-Security-Policy', csp);
  response.headers.set('x-nonce', nonce);
  return response;
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon|.*\\..*).*)'],
};
```

- [ ] **Step 2: Commit**

```bash
git add middleware.ts
git commit -m "feat: add CSP nonce middleware at project root"
```

---

### Task 3: Create root layout with theme flash prevention

**Files:**
- Create: `app/layout.tsx`
- Create: `app/globals.css` (import existing `src/index.css`)

- [ ] **Step 1: Create `app/globals.css`**

```css
/* app/globals.css — re-export existing styles */
@import '../src/index.css';
```

- [ ] **Step 2: Create `app/layout.tsx`**

```tsx
// app/layout.tsx
import './globals.css';
import { headers } from 'next/headers';
import type { Metadata } from 'next';
import { Providers } from './providers';

const THEME_SCRIPT = `(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme:dark)').matches)) {
      document.documentElement.classList.add('dark');
    }
  } catch(e) {}
})();`;

export const metadata: Metadata = {
  title: { default: 'MITRE Explorer', template: '%s — MITRE Explorer' },
  description: 'Multi-domain threat intelligence platform built on MITRE ATT&CK',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') ?? '';

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/diamond-favicon.svg" type="image/svg+xml" />
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="bg-[var(--surface-deep)] text-[var(--text-primary)]">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add app/layout.tsx app/globals.css
git commit -m "feat: root layout with theme flash prevention and CSP nonce"
```

---

### Task 4: Create providers.tsx (QueryClient, Theme, Domain, Sector, Suspense)

**Files:**
- Create: `app/providers.tsx`
- Modify: `src/contexts/ThemeContext.tsx` — fix hydration (lazy init)
- Modify: `src/contexts/DomainContext.tsx` — rewrite for `next/navigation`
- Modify: `src/contexts/SectorContext.tsx` — rewrite for `next/navigation`

- [ ] **Step 1: Rewrite `ThemeContext.tsx` for SSR hydration safety**

Replace `getInitialTheme` with lazy `useEffect` sync. The blocking script handles the CSS class; context just needs to catch up:

```tsx
// src/contexts/ThemeContext.tsx
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

type Theme = 'light' | 'dark';

interface ThemeContextValue {
  theme: Theme;
  toggle: () => void;
}

const ThemeContext = createContext<ThemeContextValue>({
  theme: 'light',
  toggle: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>('light');

  // Sync from localStorage on mount (blocking script already set CSS class)
  useEffect(() => {
    const stored = localStorage.getItem('theme') as Theme | null;
    if (stored === 'dark' || stored === 'light') {
      setTheme(stored);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
      setTheme('dark');
    }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    root.classList.toggle('dark', theme === 'dark');
    root.classList.toggle('light', theme === 'light');
    localStorage.setItem('theme', theme);
  }, [theme]);

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), []);

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}
```

- [ ] **Step 2: Rewrite `DomainContext.tsx` for `next/navigation`**

Replace `react-router-dom` imports with `next/navigation`. Replace `setSearchParams` with `router.push`:

```tsx
// src/contexts/DomainContext.tsx
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

export interface DomainOption {
  value: string;
  label: string;
  short: string;
}

const DOMAINS: DomainOption[] = [
  { value: 'enterprise-attack', label: 'Enterprise', short: 'Enterprise' },
  { value: 'mobile-attack',     label: 'Mobile',     short: 'Mobile'     },
  { value: 'ics-attack',        label: 'ICS',         short: 'ICS'        },
  { value: 'atlas-attack',      label: 'ATLAS',       short: 'ATLAS'      },
  { value: 'all',               label: 'All Domains', short: 'All'        },
];

export const DEFAULT_DOMAIN = 'enterprise-attack';
const STORAGE_KEY = 'mitre-domain';

interface DomainContextValue {
  domain: string;
  setDomain: (slug: string) => void;
  domainParam: Record<string, string>;
  domains: DomainOption[];
}

const Ctx = createContext<DomainContextValue>({
  domain: DEFAULT_DOMAIN,
  setDomain: () => {},
  domainParam: { domain: DEFAULT_DOMAIN },
  domains: DOMAINS,
});

export function DomainProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const urlDomain = searchParams.get('domain') ?? null;

  const [storedDomain, setStoredDomain] = useState<string | null>(() =>
    typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_KEY) : null
  );

  const domain = urlDomain ?? storedDomain ?? DEFAULT_DOMAIN;

  useEffect(() => {
    if (urlDomain) {
      sessionStorage.setItem(STORAGE_KEY, urlDomain);
      setStoredDomain(urlDomain);
    }
  }, [urlDomain]);

  // URL re-injection is now handled by providers.tsx merged effect — removed from here

  const setDomain = useCallback(
    (slug: string) => {
      sessionStorage.setItem(STORAGE_KEY, slug);
      setStoredDomain(slug);
      const params = new URLSearchParams(searchParams.toString());
      if (slug === DEFAULT_DOMAIN) {
        params.delete('domain');
      } else {
        params.set('domain', slug);
      }
      router.push(`${pathname}?${params.toString()}`);
    },
    [searchParams, router, pathname],
  );

  const domainParam = useMemo<Record<string, string>>(
    () => (domain === 'all' ? {} as Record<string, string> : { domain }),
    [domain],
  );

  const value = useMemo(
    () => ({ domain, setDomain, domainParam, domains: DOMAINS }),
    [domain, setDomain, domainParam],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useDomain() {
  return useContext(Ctx);
}
```

- [ ] **Step 3: Rewrite `SectorContext.tsx` for `next/navigation`**

Same pattern — replace `setSearchParams` with `router.push`:

```tsx
// src/contexts/SectorContext.tsx
import { createContext, useContext, useCallback, useMemo, useEffect, useState, type ReactNode } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

interface SectorContextValue {
  sector: string | null;
  setSector: (slug: string | null) => void;
  sectorParam: Record<string, string>;
}

const Ctx = createContext<SectorContextValue>({
  sector: null,
  setSector: () => {},
  sectorParam: {},
});

const EMPTY_PARAM: Record<string, string> = {};
const STORAGE_KEY = 'mitre-sector';

export function SectorProvider({ children }: { children: ReactNode }) {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const urlSector = searchParams.get('sector') || null;

  const [storedSector, setStoredSector] = useState<string | null>(() =>
    typeof window !== 'undefined' ? sessionStorage.getItem(STORAGE_KEY) : null
  );
  const sector = urlSector ?? storedSector;

  useEffect(() => {
    if (urlSector) {
      sessionStorage.setItem(STORAGE_KEY, urlSector);
    }
  }, [urlSector]);

  // URL re-injection is now handled by providers.tsx merged effect — removed from here

  const setSector = useCallback(
    (slug: string | null) => {
      if (slug) {
        sessionStorage.setItem(STORAGE_KEY, slug);
      } else {
        sessionStorage.removeItem(STORAGE_KEY);
      }
      setStoredSector(slug);
      const params = new URLSearchParams(searchParams.toString());
      if (slug) {
        params.set('sector', slug);
      } else {
        params.delete('sector');
      }
      router.push(`${pathname}?${params.toString()}`);
    },
    [searchParams, router, pathname],
  );

  const sectorParam = useMemo<Record<string, string>>(
    () => (sector ? { sector } : EMPTY_PARAM),
    [sector],
  );

  const value = useMemo(
    () => ({ sector, setSector, sectorParam }),
    [sector, setSector, sectorParam],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSector() {
  return useContext(Ctx);
}
```

- [ ] **Step 4: Create `app/providers.tsx`**

```tsx
// app/providers.tsx
'use client';

import { useState, Suspense, useEffect } from 'react';
import { useSearchParams, useRouter, usePathname } from 'next/navigation';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '../src/contexts/ThemeContext';
import { DomainProvider, DEFAULT_DOMAIN } from '../src/contexts/DomainContext';
import { SectorProvider } from '../src/contexts/SectorContext';
import { DiamondLoader } from '../src/components/shared/FoldingDiamond';
import { Analytics } from '@vercel/analytics/react';

function UrlSyncEffect() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  useEffect(() => {
    const params = new URLSearchParams(searchParams.toString());
    let changed = false;

    const storedDomain = sessionStorage.getItem('mitre-domain');
    if (storedDomain && storedDomain !== DEFAULT_DOMAIN && !params.has('domain')) {
      params.set('domain', storedDomain);
      changed = true;
    }

    const storedSector = sessionStorage.getItem('mitre-sector');
    if (storedSector && !params.has('sector')) {
      params.set('sector', storedSector);
      changed = true;
    }

    if (changed) {
      router.replace(`${pathname}?${params.toString()}`);
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  return null;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 5 * 60 * 1000,
        gcTime: 30 * 60 * 1000,
        retry: 2,
      },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <Suspense fallback={<DiamondLoader text="Loading..." />}>
          <DomainProvider>
            <SectorProvider>
              <UrlSyncEffect />
              {children}
            </SectorProvider>
          </DomainProvider>
        </Suspense>
      </ThemeProvider>
      <Analytics />
    </QueryClientProvider>
  );
}
```

- [ ] **Step 5: Verify `npm run dev` starts without errors**

```bash
npm run dev
```

Expected: Next.js dev server starts. May show warnings about missing pages — that's OK.

- [ ] **Step 6: Commit**

```bash
git add app/providers.tsx src/contexts/ThemeContext.tsx src/contexts/DomainContext.tsx src/contexts/SectorContext.tsx
git commit -m "feat: providers.tsx with QueryClient, theme, domain, sector, URL sync"
```

---

### Task 5: Create error and 404 pages

**Files:**
- Create: `app/not-found.tsx`
- Create: `app/error.tsx`

- [ ] **Step 1: Create `app/not-found.tsx`**

```tsx
// app/not-found.tsx
import Link from 'next/link';

export default function NotFound() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-teal)] text-4xl font-light mb-2">404 - Not Found</div>
        <div className="text-[var(--text-secondary)] text-sm mb-4">The page you are looking for does not exist.</div>
        <Link href="/" className="text-sm text-[var(--accent-teal)] hover:underline">
          Go to 360 Views →
        </Link>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Create `app/error.tsx`**

```tsx
// app/error.tsx
'use client';

export default function Error({ error, reset }: { error: Error; reset: () => void }) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-orange)] text-xl font-medium mb-2">Something went wrong</div>
        <p className="text-[var(--text-secondary)] text-sm mb-4">{error.message}</p>
        <button
          onClick={reset}
          className="px-4 py-2 text-sm rounded-md border border-[var(--border-color)] text-[var(--text-primary)] hover:border-[var(--accent-teal)] transition-colors"
        >
          Try again
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 3: Commit**

```bash
git add app/not-found.tsx app/error.tsx
git commit -m "feat: custom 404 and error pages"
```

---

### Task 6: Create API utility libs (handler + CORS)

**Files:**
- Create: `app/api/lib/handler.ts`
- Create: `app/api/lib/cors.ts`

- [ ] **Step 1: Create `app/api/lib/handler.ts`**

```ts
// app/api/lib/handler.ts
import { NextResponse } from 'next/server';

export function jsonResponse(data: unknown, cacheTtl?: number) {
  const headers: Record<string, string> = {};
  if (cacheTtl) {
    headers['Cache-Control'] = `public, s-maxage=${cacheTtl}, stale-while-revalidate=86400`;
  }
  return NextResponse.json(data, { headers });
}

export function errorResponse(status: number, error: string, code: string) {
  return NextResponse.json({ error, code }, { status });
}
```

- [ ] **Step 2: Create `app/api/lib/cors.ts`**

```ts
// app/api/lib/cors.ts
import { NextResponse } from 'next/server';

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Cron-Secret',
};

export function corsOptions() {
  return new NextResponse(null, { status: 204, headers: CORS_HEADERS });
}

export function withCors(response: NextResponse): NextResponse {
  Object.entries(CORS_HEADERS).forEach(([k, v]) => response.headers.set(k, v));
  return response;
}
```

- [ ] **Step 3: Commit**

```bash
git add app/api/lib/handler.ts app/api/lib/cors.ts
git commit -m "feat: API handler utilities (jsonResponse, CORS)"
```

---

### Task 7: Migrate dashboard API + page as spike

**Files:**
- Create: `app/api/v1/dashboard/route.ts` (migrated from `api/v1/dashboard.ts`)
- Create: `app/dashboard/page.tsx`
- Copy: `api/v1/lib/db.ts` → `app/api/v1/lib/db.ts`
- Copy: `api/v1/lib/middleware.ts` is NOT copied — replaced by `app/api/lib/handler.ts`

- [ ] **Step 1: Copy ALL shared API libs (dashboard may import siblings)**

```bash
mkdir -p app/api/v1/lib
cp api/v1/lib/db.ts app/api/v1/lib/db.ts
cp api/v1/lib/validate.ts app/api/v1/lib/validate.ts
cp api/v1/lib/queries.ts app/api/v1/lib/queries.ts
cp api/v1/lib/types.ts app/api/v1/lib/types.ts
cp api/v1/lib/getParentId.ts app/api/v1/lib/getParentId.ts
```

- [ ] **Step 2: Migrate dashboard API endpoint**

Read `api/v1/dashboard.ts`, then create the route handler version. The key changes:
- `import type { VercelRequest, VercelResponse }` → removed
- `export default withHandler(handler, ...)` → `export async function GET(req: NextRequest)`
- `req.query.xxx` → `req.nextUrl.searchParams.get('xxx')`
- `res.status(200).json(data)` → `return withCors(jsonResponse(data, 3600))`

```bash
# Read the existing file first to understand the exact queries
cat api/v1/dashboard.ts
```

Create `app/api/v1/dashboard/route.ts` with the converted signature. Copy the query logic verbatim; only change the wrapper.

- [ ] **Step 3: Create dashboard page**

```tsx
// app/dashboard/page.tsx
import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';

export const metadata: Metadata = {
  title: 'Overview',
  description: 'Summary statistics, top threat groups, technique distribution, and sector breakdown across the ATT&CK knowledge base',
};

// Dashboard is Tier 3 — static metadata, client render
// Import existing page component directly (it will need 'use client' directive)
import { Dashboard as DashboardClient } from '../../src/pages/Dashboard';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading dashboard..." />}>
      <DashboardClient />
    </Suspense>
  );
}
```

- [ ] **Step 4: Add `'use client'` to `src/pages/Dashboard.tsx`**

Add `'use client';` as the very first line of `src/pages/Dashboard.tsx`.

- [ ] **Step 5: Verify — `npm run dev`, navigate to `/dashboard`**

```bash
npm run dev
# Open http://localhost:3000/dashboard — should render the dashboard
```

- [ ] **Step 5: Commit**

```bash
git add app/api/v1/lib/db.ts app/api/v1/dashboard/route.ts app/dashboard/page.tsx src/pages/Dashboard.tsx
git commit -m "feat: spike — dashboard API + page migrated to Next.js"
```

---

### Task 8: SEO — sitemap + robots + Phase 0 gate

**Files:**
- Create: `app/sitemap.ts`
- Create: `app/robots.ts`
- Create: `app/page.tsx` (landing page — placeholder for now)

- [ ] **Step 1: Create `app/robots.ts`**

```ts
// app/robots.ts
import type { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/', disallow: ['/api/', '/search'] },
    sitemap: 'https://mitre-explorer.org/sitemap.xml',
  };
}
```

- [ ] **Step 2: Create `app/sitemap.ts`**

```ts
// app/sitemap.ts
import type { MetadataRoute } from 'next';
import { query } from './api/v1/lib/db';

const BASE_URL = 'https://mitre-explorer.org';

export default async function sitemap(): Promise<MetadataRoute.Sitemap> {
  const staticPages = [
    '', '/dashboard', '/matrix', '/techniques', '/groups', '/campaigns',
    '/software', '/mitigations', '/tactics', '/sectors', '/applications',
    '/search', '/cti/cves', '/cti/reports', '/cti/iocs', '/cti/sigma',
    '/cti/feed-status', '/frameworks/owasp', '/frameworks/nist',
    '/frameworks/engage', '/frameworks/react', '/frameworks/veris',
    '/frameworks/cloud', '/frameworks/atomic', '/frameworks/detection',
    '/external-actors', '/data-sources',
  ].map((path) => ({ url: `${BASE_URL}${path}`, changeFrequency: 'weekly' as const }));

  // Dynamic pages from DB
  const [techniques, groups, cves] = await Promise.all([
    query<{ attack_id: string }>('SELECT attack_id FROM techniques WHERE attack_id IS NOT NULL'),
    query<{ attack_id: string }>('SELECT attack_id FROM threat_groups WHERE attack_id IS NOT NULL'),
    query<{ cve_id: string }>("SELECT cve_id FROM cves WHERE cve_id IS NOT NULL ORDER BY published_at DESC LIMIT 5000"),
  ]);

  const techniqueUrls = techniques.rows.map((t) => ({
    url: `${BASE_URL}/techniques/${t.attack_id}`,
    changeFrequency: 'monthly' as const,
  }));

  const groupUrls = groups.rows.map((g) => ({
    url: `${BASE_URL}/groups/${g.attack_id}`,
    changeFrequency: 'monthly' as const,
  }));

  const cveUrls = cves.rows.map((c) => ({
    url: `${BASE_URL}/cti/cves/${c.cve_id}`,
    changeFrequency: 'weekly' as const,
  }));

  return [...staticPages, ...techniqueUrls, ...groupUrls, ...cveUrls];
}
```

- [ ] **Step 3: Create `app/page.tsx` (landing page placeholder)**

```tsx
// app/page.tsx
import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../src/components/shared/FoldingDiamond';

export const metadata: Metadata = {
  title: '360 Views — MITRE Explorer',
  description: 'Search any entity and explore its relationships — technique maps, actor profiles, application maps, and force-directed graphs',
};

// Relationships is the landing page — Tier 2, client-rendered
import { Relationships } from '../src/pages/Relationships';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <Relationships />
    </Suspense>
  );
}
```

- [ ] **Step 4: Phase 0 gate — verify everything works**

```bash
npm run dev
# Check these manually:
# 1. http://localhost:3000 — renders (may have React Router errors — expected, we haven't removed it yet)
# 2. http://localhost:3000/dashboard — renders dashboard
# 3. http://localhost:3000/api/v1/dashboard — returns JSON
# 4. http://localhost:3000/sitemap.xml — returns XML with technique/group URLs
# 5. http://localhost:3000/robots.txt — returns robots directives
# 6. View source of /dashboard — should have <title> and <meta> in HTML
```

- [ ] **Step 5: Commit**

```bash
git add app/sitemap.ts app/robots.ts app/page.tsx
git commit -m "feat: sitemap, robots.txt, landing page — Phase 0 complete"
```

---

## Chunk 2: Phase 1 — API Layer

### Task 9: Copy cron shared libs

**Files:**
- Copy: `api/cron/lib/auth.ts` → `app/api/cron/lib/auth.ts`
- Copy: `api/cron/lib/capec-bridge.ts` → `app/api/cron/lib/capec-bridge.ts`

> **Note:** `api/v1/lib/` files were already copied in Task 7 (Phase 0 spike).

- [ ] **Step 1: Copy cron libs**

```bash
mkdir -p app/api/cron/lib
cp api/cron/lib/auth.ts app/api/cron/lib/auth.ts
cp api/cron/lib/capec-bridge.ts app/api/cron/lib/capec-bridge.ts
```

- [ ] **Step 2: Verify import paths are correct (relative paths should be preserved)**

- [ ] **Step 3: Commit**

```bash
git add app/api/cron/lib/
git commit -m "feat: copy cron shared libs to app/api/"
```

---

### Task 10: Migrate v1 API endpoints (batch — 60+ files)

**Files:**
- Create: `app/api/v1/*/route.ts` for each endpoint

This is the largest mechanical task. Each endpoint follows the same conversion pattern:

**Conversion pattern for every endpoint:**

1. Read the old file (e.g., `api/v1/matrix.ts`)
2. Create `app/api/v1/matrix/route.ts`
3. Apply these transforms:
   - Remove `import type { VercelRequest, VercelResponse } from '@vercel/node'`
   - Remove `import { withHandler } from './lib/middleware'`
   - Add `import { NextRequest } from 'next/server'`
   - Add `import { jsonResponse, errorResponse } from '../../lib/handler'` (adjust path)
   - Add `import { corsOptions, withCors } from '../../lib/cors'` (adjust path)
   - `export default withHandler(handler, { cacheTtl: N })` → `export async function GET(req: NextRequest) { ... return withCors(jsonResponse(data, N)); }`
   - `export { corsOptions as OPTIONS };`
   - `req.query.xxx as string` → `req.nextUrl.searchParams.get('xxx')`
   - `res.status(200).json(data)` → `return withCors(jsonResponse(data))`
   - `res.status(400).json(...)` → `return errorResponse(400, '...', 'BAD_REQUEST')`
   - For dynamic routes: `{ params }: { params: Promise<{ attackId: string }> }` → `const { attackId } = await params`

**File mapping (flat → directory-based):**

| Old path | New path |
|----------|----------|
| `api/v1/dashboard.ts` | `app/api/v1/dashboard/route.ts` (done in Task 7) |
| `api/v1/matrix.ts` | `app/api/v1/matrix/route.ts` |
| `api/v1/cves.ts` | `app/api/v1/cves/route.ts` |
| `api/v1/entities.ts` | `app/api/v1/entities/route.ts` |
| `api/v1/procedures.ts` | `app/api/v1/procedures/route.ts` |
| `api/v1/search.ts` | `app/api/v1/search/route.ts` |
| `api/v1/site-health.ts` | `app/api/v1/site-health/route.ts` |
| `api/v1/techniques/index.ts` | `app/api/v1/techniques/route.ts` |
| `api/v1/techniques/[attackId].ts` | `app/api/v1/techniques/[attackId]/route.ts` |
| `api/v1/groups/index.ts` | `app/api/v1/groups/route.ts` |
| `api/v1/groups/[attackId].ts` | `app/api/v1/groups/[attackId]/route.ts` |
| ... (same pattern for all) ... |
| `api/v1/applications/index.ts` | `app/api/v1/applications/route.ts` |
| `api/v1/applications/[...slug].ts` | `app/api/v1/applications/[...slug]/route.ts` |
| `api/v1/frameworks/owasp.ts` | `app/api/v1/frameworks/owasp/route.ts` |
| `api/v1/frameworks/owasp/[categoryId].ts` | `app/api/v1/frameworks/owasp/[categoryId]/route.ts` |

- [ ] **Step 1: Migrate all flat v1 endpoints (matrix, cves, entities, procedures, search, site-health)**

For each: create directory, create `route.ts`, apply conversion pattern above.

- [ ] **Step 2: Migrate all CRUD endpoints (techniques, groups, campaigns, software, mitigations, tactics, sectors, data-sources, external-actors)**

For each entity: migrate both `index.ts` → `route.ts` and `[attackId].ts` → `[attackId]/route.ts`.

- [ ] **Step 3: Migrate nested endpoints (cves/[cveId], relationships/[attackId], feed/*, frameworks/*)**

Pay attention to deep nesting: `api/v1/feed/iocs/[iocId]/techniques.ts` → `app/api/v1/feed/iocs/[iocId]/techniques/route.ts`.

- [ ] **Step 4: Migrate applications catch-all**

`api/v1/applications/[...slug].ts` → `app/api/v1/applications/[...slug]/route.ts`

The `vercel.json` rewrite `{ "source": "/api/v1/applications/:vendor/:product", "destination": "/api/v1/applications/[...slug]" }` is no longer needed — Next.js catch-all routes handle this natively.

- [ ] **Step 5: Migrate export endpoint**

`api/v1/export/[entityType].ts` → `app/api/v1/export/[entityType]/route.ts`

- [ ] **Step 6: Verify — spot-check 5 endpoints**

```bash
npm run dev
# Test:
# curl http://localhost:3000/api/v1/techniques?limit=2
# curl http://localhost:3000/api/v1/groups/G0016
# curl http://localhost:3000/api/v1/cves?limit=2
# curl http://localhost:3000/api/v1/frameworks/owasp
# curl http://localhost:3000/api/v1/search?q=phishing
```

- [ ] **Step 7: Commit**

```bash
git add app/api/v1/
git commit -m "feat: migrate all 60+ v1 API endpoints to Next.js route handlers"
```

---

### Task 11: Migrate A2A protocol

**Files:**
- Create: `app/api/a2a/route.ts` (from `api/a2a/index.ts`)

- [ ] **Step 1: Read existing A2A handler**

```bash
cat api/a2a/index.ts
```

- [ ] **Step 2: Create `app/api/a2a/route.ts`**

Key changes:
- `export default handler` → `export async function POST(req: NextRequest)`
- `export { corsOptions as OPTIONS }` for CORS preflight
- `req.body` → `await req.json()`
- `res.status(200).json(result)` → `return withCors(NextResponse.json(result))`
- `callInternalApi()` — replace hardcoded domain with `process.env.NEXT_PUBLIC_SITE_URL || process.env.VERCEL_URL ? \`https://${process.env.VERCEL_URL}\` : 'http://localhost:3000'`
- Remove `export const config = { api: { bodyParser: ... } }`

- [ ] **Step 3: Verify A2A**

```bash
curl -X POST http://localhost:3000/api/a2a \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tasks/send","id":"test","params":{"id":"t1","message":{"role":"user","parts":[{"type":"text","text":"list 3 techniques"}]}}}'
```

- [ ] **Step 4: Commit**

```bash
git add app/api/a2a/route.ts
git commit -m "feat: migrate A2A protocol to Next.js route handler"
```

---

### Task 12: Migrate cron handlers

**Files:**
- Create: `app/api/cron/*/route.ts` for each cron job (9 files)

- [ ] **Step 1: Migrate all 9 cron handlers**

For each cron handler in `api/cron/`:
- `ingest-otx.ts` → `app/api/cron/ingest-otx/route.ts`
- `ingest-abuse-ch.ts` → `app/api/cron/ingest-abuse-ch/route.ts`
- `ingest-cisa-kev.ts` → `app/api/cron/ingest-cisa-kev/route.ts`
- `ingest-rss.ts` → `app/api/cron/ingest-rss/route.ts`
- `sync-d3fend.ts` → `app/api/cron/sync-d3fend/route.ts`
- `enrich-nvd.ts` → `app/api/cron/enrich-nvd/route.ts`
- `enrich-vt.ts` → `app/api/cron/enrich-vt/route.ts`
- `ingest-cve-delta.ts` → `app/api/cron/ingest-cve-delta/route.ts`
- `scan-site-health.ts` → `app/api/cron/scan-site-health/route.ts`

Key changes per file:
- **Export `GET` not `POST`** — Vercel crons send GET requests
- Add `export const maxDuration = 300;` for long-running jobs
- `export default withHandler(handler)` → `export async function GET(req: NextRequest)`
- Cron auth check: `req.headers['x-vercel-cron-secret']` → `req.headers.get('x-vercel-cron-secret')`

- [ ] **Step 2: Commit**

```bash
git add app/api/cron/
git commit -m "feat: migrate 9 cron handlers (export GET, maxDuration)"
```

---

### Task 13: Delete agent-card.ts, update vercel.json

**Files:**
- Delete: `api/agent-card.ts`
- Modify: `vercel.json`

- [ ] **Step 1: Delete `api/agent-card.ts`**

`public/.well-known/agent-card.json` is served statically by Next.js.

```bash
rm api/agent-card.ts
```

- [ ] **Step 2: Slim `vercel.json`**

Remove `framework`, `buildCommand`, `outputDirectory`, `rewrites`, `functions`, and CSP header. Keep crons + security headers (minus CSP):

```json
{
  "crons": [
    { "path": "/api/cron/ingest-otx", "schedule": "0 */3 * * *" },
    { "path": "/api/cron/ingest-abuse-ch", "schedule": "0 2 * * *" },
    { "path": "/api/cron/ingest-cisa-kev", "schedule": "0 3 * * *" },
    { "path": "/api/cron/ingest-rss", "schedule": "0 */6 * * *" },
    { "path": "/api/cron/sync-d3fend", "schedule": "0 6 1 * *" },
    { "path": "/api/cron/enrich-nvd", "schedule": "0 */4 * * *" },
    { "path": "/api/cron/enrich-vt", "schedule": "30 */8 * * *" },
    { "path": "/api/cron/ingest-cve-delta", "schedule": "0 4 * * *" },
    { "path": "/api/cron/scan-site-health", "schedule": "0 12 * * *" }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-XSS-Protection", "value": "0" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" }
      ]
    }
  ]
}
```

- [ ] **Step 3: Commit + tag for rollback**

```bash
git add -u
git add vercel.json
git commit -m "feat: slim vercel.json, delete agent-card.ts — Phase 1 complete"
git tag pre-migration-phase1
```

---

## Chunk 3: Phase 2a — Contexts + Layout + Sidebar

### Task 14: Extract AppShell from App.tsx Layout

**Files:**
- Create: `src/components/layout/AppShell.tsx`
- Modify: `app/layout.tsx` — wrap children in AppShell

- [ ] **Step 1: Create `AppShell.tsx`**

Extract the `Layout` function from `src/App.tsx` (lines 109-249) into a standalone `'use client'` component. Replace `<Outlet />` with `{children}`. Keep: sidebar state, header, SearchBar, VtBadge, ThemeToggle, modals, print watermark.

```tsx
// src/components/layout/AppShell.tsx
'use client';

import { useState, useEffect } from 'react';
import { Sidebar } from './Sidebar';
import { SearchBar } from './SearchBar';
import { RelationshipModel } from '../relationships/RelationshipModel';
import { useTheme } from '../../contexts/ThemeContext';

function VtBadge() {
  // ... exact copy from App.tsx lines 60-82
}

function ThemeToggle() {
  // ... exact copy from App.tsx lines 85-106
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[var(--surface-deep)]">
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/60 lg:hidden" onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      )}
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      <div className="flex-1 flex flex-col lg:ml-52 min-h-screen">
        <header className="sticky top-0 z-30 flex items-center gap-2 md:gap-4 px-3 md:px-6 py-2 md:py-3 bg-[var(--surface-card)] shadow-sm border-b border-[var(--border-color)]">
          {/* ... exact header from App.tsx */}
          <button type="button" aria-label="Open navigation menu" onClick={() => setSidebarOpen(true)} className="lg:hidden flex-shrink-0 p-1 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" /></svg>
          </button>
          <SearchBar />
          <button type="button" onClick={() => setModelOpen(true)} className="hidden md:block flex-shrink-0 px-3 py-1.5 text-xs rounded-md border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors" title="ATT&CK data model — entity relationships">Data Model</button>
          <div className="flex-1" />
          <div className="hidden md:block"><VtBadge /></div>
          <ThemeToggle />
          <button type="button" onClick={() => setHelpOpen(true)} data-print-hide className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors" title="About this application">?</button>
        </header>
        <main className="flex-1 px-3 md:px-6 py-4 md:py-6 overflow-y-auto overflow-x-hidden">
          {children}
        </main>
        {/* Print watermark */}
        <div className="print-watermark hidden fixed bottom-4 right-6 items-center gap-2 opacity-60" style={{ zIndex: 9999 }}>
          {/* ... exact copy from App.tsx */}
        </div>
      </div>
      <RelationshipModel open={modelOpen} onClose={() => setModelOpen(false)} />
      {helpOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setHelpOpen(false)}>
          {/* ... exact help modal from App.tsx lines 202-245 */}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 2: Update `app/providers.tsx` to include AppShell**

Add `AppShell` wrapping `{children}` inside providers:

```tsx
import { AppShell } from '../src/components/layout/AppShell';

// In the return:
<SectorProvider>
  <UrlSyncEffect />
  <AppShell>{children}</AppShell>
</SectorProvider>
```

- [ ] **Step 3: Commit**

```bash
git add src/components/layout/AppShell.tsx app/providers.tsx
git commit -m "feat: extract AppShell from App.tsx Layout"
```

---

### Task 15: Rewrite Sidebar.tsx — NavLink → usePathname

**Files:**
- Modify: `src/components/layout/Sidebar.tsx`

- [ ] **Step 1: Replace imports**

```tsx
// BEFORE
import { NavLink, useLocation } from 'react-router-dom';

// AFTER
import Link from 'next/link';
import { usePathname } from 'next/navigation';
```

- [ ] **Step 2: Replace `NavLink` usage**

Every `<NavLink to={path} ...>` → `<Link href={path} ...>` with manual `isActive`:

```tsx
const pathname = usePathname();
const isActive = pathname === path || pathname.startsWith(path + '/');
// Apply active class based on isActive instead of NavLink's className callback
```

- [ ] **Step 3: Replace `useLocation()` with `usePathname()`**

All `const location = useLocation()` → `const pathname = usePathname()`, `location.pathname` → `pathname`.

- [ ] **Step 4: Fix `window.innerWidth` hydration in `CollapsibleNavSection`**

```tsx
// BEFORE
const isMobile = typeof window !== 'undefined' && window.innerWidth < 1024;
const [open, setOpen] = useState(isMobile ? isActiveRoute : (defaultOpen || isActiveRoute));

// AFTER
const [open, setOpen] = useState(defaultOpen || isActiveRoute);
useEffect(() => {
  if (window.innerWidth < 1024 && !isActiveRoute) setOpen(false);
}, []); // eslint-disable-line react-hooks/exhaustive-deps
```

- [ ] **Step 5: Add `'use client'` directive if not present**

- [ ] **Step 6: Commit**

```bash
git add src/components/layout/Sidebar.tsx
git commit -m "feat: sidebar — NavLink→usePathname, fix window.innerWidth hydration"
```

---

### Task 16: Rewrite SearchBar.tsx — useNavigate → useRouter

**Files:**
- Modify: `src/components/layout/SearchBar.tsx`

- [ ] **Step 1: Replace imports**

```tsx
// BEFORE
import { useNavigate } from 'react-router-dom';

// AFTER
import { useRouter } from 'next/navigation';
```

- [ ] **Step 2: Replace `useNavigate()` calls**

```tsx
// BEFORE
const navigate = useNavigate();
navigate(`/techniques/${attackId}`);

// AFTER
const router = useRouter();
router.push(`/techniques/${attackId}`);
```

- [ ] **Step 3: Add `'use client'` if not present**

- [ ] **Step 4: Commit**

```bash
git add src/components/layout/SearchBar.tsx
git commit -m "feat: SearchBar — useNavigate→useRouter"
```

---

### Task 17: Replace Link imports across all components

**Files:**
- Modify: ~20 component files that import `Link` from `react-router-dom`

- [ ] **Step 1: Find all `Link` imports from react-router-dom**

```bash
grep -rn "from 'react-router-dom'" src/components/ --include="*.tsx" -l
```

- [ ] **Step 2: For each file**

```tsx
// BEFORE
import { Link } from 'react-router-dom';
<Link to={path}>

// AFTER
import Link from 'next/link';
<Link href={path}>
```

Key files: `EntityLink.tsx`, `StatCard.tsx`, plus any component with router `Link`.

- [ ] **Step 3: Replace `useNavigate` in remaining components**

Check `RelationshipModel.tsx` and any other component files.

- [ ] **Step 4: Commit**

```bash
git add src/components/
git commit -m "feat: replace react-router Link with next/link across components"
```

---

### Task 18: Remove usePageTitle from all 37 pages

**Files:**
- Modify: 36 page files in `src/pages/`
- Delete: `src/hooks/usePageTitle.ts`

- [ ] **Step 1: Remove `usePageTitle` calls from all pages**

For each of the 37 files:
- Remove `import { usePageTitle } from '../hooks/usePageTitle';`
- Remove the `usePageTitle('...');` call

This is mechanical — can be done with search-and-replace.

- [ ] **Step 2: Delete the hook file**

```bash
rm src/hooks/usePageTitle.ts
```

- [ ] **Step 3: Verify — no remaining references**

```bash
grep -rn "usePageTitle" src/
# Should return 0 results
```

- [ ] **Step 4: Commit**

```bash
git add -u
git commit -m "refactor: remove usePageTitle from all 37 pages (replaced by generateMetadata)"
```

---

### Task 19: Wrap D3/recharts with dynamic ssr:false

**Files:**
- Modify: files that import `ForceGraph`, recharts components, or `dompurify`

- [ ] **Step 1: Identify all D3/recharts imports that need wrapping**

```bash
grep -rn "import.*ForceGraph" src/ --include="*.tsx"
grep -rn "from 'recharts'" src/ --include="*.tsx"
grep -rn "from 'dompurify'" src/ --include="*.tsx"
```

- [ ] **Step 2: Wrap ForceGraph with `next/dynamic`**

In the files that import ForceGraph (likely `Relationships.tsx` or a wrapper):

```tsx
import dynamic from 'next/dynamic';
const ForceGraph = dynamic(() => import('../components/graph/ForceGraph'), { ssr: false });
```

- [ ] **Step 3: Wrap recharts components similarly**

For any file directly importing from `recharts` that is rendered via SSR. Since all pages will be `'use client'`, this may not be strictly needed — but wrap at the component level if hydration mismatches occur.

- [ ] **Step 4: Commit**

```bash
git add src/
git commit -m "feat: wrap D3/recharts with next/dynamic ssr:false"
```

---

## Chunk 4: Phase 2b — Tier 1 SSR Pages

### Task 20: Create server-side data fetch utilities

**Files:**
- Create: `app/lib/data.ts`

- [ ] **Step 1: Create `app/lib/data.ts` with `cache()` wrappers**

```ts
// app/lib/data.ts
import { cache } from 'react';
import { query } from '../api/v1/lib/db';

export const fetchTechnique = cache(async (attackId: string) => {
  const result = await query(
    `SELECT t.*, array_agg(DISTINCT d.domain) as domains
     FROM techniques t
     LEFT JOIN technique_domains d ON d.technique_id = t.id
     WHERE t.attack_id = $1
     GROUP BY t.id`,
    [attackId]
  );
  return result.rows[0] ?? null;
});

export const fetchGroup = cache(async (attackId: string) => {
  const result = await query(
    'SELECT * FROM threat_groups WHERE attack_id = $1',
    [attackId]
  );
  return result.rows[0] ?? null;
});

export const fetchCve = cache(async (cveId: string) => {
  const result = await query(
    'SELECT * FROM cves WHERE cve_id = $1',
    [cveId]
  );
  return result.rows[0] ?? null;
});

export const fetchCampaign = cache(async (attackId: string) => {
  const result = await query('SELECT * FROM campaigns WHERE attack_id = $1', [attackId]);
  return result.rows[0] ?? null;
});

export const fetchSoftware = cache(async (attackId: string) => {
  const result = await query('SELECT * FROM software WHERE attack_id = $1', [attackId]);
  return result.rows[0] ?? null;
});

export const fetchMitigation = cache(async (attackId: string) => {
  const result = await query('SELECT * FROM mitigations WHERE attack_id = $1', [attackId]);
  return result.rows[0] ?? null;
});

export const fetchTactic = cache(async (attackId: string) => {
  const result = await query('SELECT * FROM tactics WHERE attack_id = $1', [attackId]);
  return result.rows[0] ?? null;
});

export const fetchDataSource = cache(async (attackId: string) => {
  const result = await query('SELECT * FROM data_sources WHERE attack_id = $1', [attackId]);
  return result.rows[0] ?? null;
});

export const fetchSector = cache(async (slug: string) => {
  const result = await query('SELECT * FROM sectors WHERE slug = $1', [slug]);
  return result.rows[0] ?? null;
});

export const fetchOwaspCategory = cache(async (categoryId: string) => {
  const result = await query('SELECT * FROM owasp_top10 WHERE UPPER(category_id) = UPPER($1)', [categoryId]);
  return result.rows[0] ?? null;
});
```

> **Note:** The exact SQL queries should match what the corresponding API detail endpoints return. Read each `api/v1/*/[attackId].ts` to get the exact query. The above are simplified — the implementor must copy the real queries.

- [ ] **Step 2: Commit**

```bash
git add app/lib/data.ts
git commit -m "feat: server-side cache() wrapped data fetch utilities"
```

---

### Task 21: Migrate Tier 1 detail pages (10 entity types)

**Files:**
- Create: `app/techniques/[attackId]/page.tsx`
- Create: `app/groups/[attackId]/page.tsx`
- Create: `app/campaigns/[attackId]/page.tsx`
- Create: `app/software/[attackId]/page.tsx`
- Create: `app/mitigations/[attackId]/page.tsx`
- Create: `app/tactics/[attackId]/page.tsx`
- Create: `app/data-sources/[attackId]/page.tsx`
- Create: `app/sectors/[sectorName]/page.tsx`
- Create: `app/cti/cves/[cveId]/page.tsx`
- Create: `app/frameworks/owasp/[categoryId]/page.tsx`
- Modify: corresponding `src/pages/*.tsx` — add `'use client'`, accept `initialData` prop

Each follows the same pattern:

- [ ] **Step 1: Create technique detail page (template for all)**

```tsx
// app/techniques/[attackId]/page.tsx
import { notFound } from 'next/navigation';
import { fetchTechnique } from '../../lib/data';
import { TechniqueDetail } from '../../../src/pages/TechniqueDetail';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);
  if (!data) return { title: 'Not Found' };
  return {
    title: `${data.attack_id} ${data.name}`,
    description: data.description?.slice(0, 160) ?? `${data.attack_id} ${data.name} — ATT&CK technique details`,
    openGraph: { title: `${data.attack_id} ${data.name}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);
  if (!data) notFound();
  return <TechniqueDetail />;
}
```

> **Note:** Initially, detail pages can render the existing client component without passing `initialData` — React Query inside the component will fetch data client-side as before. The `generateMetadata` provides the SEO title/description from SSR. Passing `initialData` as a prop is an optimization that can be done in a follow-up pass.

- [ ] **Step 2: Add `'use client'` to each detail page component**

Add `'use client';` to the top of:
- `src/pages/TechniqueDetail.tsx`
- `src/pages/GroupDetail.tsx`
- `src/pages/CampaignDetail.tsx`
- `src/pages/SoftwareDetail.tsx`
- `src/pages/MitigationDetail.tsx`
- `src/pages/TacticDetail.tsx`
- `src/pages/DataSourceDetail.tsx`
- `src/pages/SectorDetail.tsx`
- `src/pages/CveDetail.tsx`
- `src/pages/OwaspTop10.tsx`

Also replace `useParams` from `react-router-dom` with `useParams` from `next/navigation` in each.

- [ ] **Step 3: Create remaining 9 detail pages**

Follow the technique template for groups, campaigns, software, mitigations, tactics, data-sources, sectors, CVEs, and OWASP. Adjust the fetch function, param name, and metadata format.

- [ ] **Step 4: Commit**

```bash
git add app/techniques/ app/groups/ app/campaigns/ app/software/ app/mitigations/ app/tactics/ app/data-sources/ app/sectors/ app/cti/cves/ app/frameworks/owasp/ src/pages/
git commit -m "feat: Tier 1 SSR detail pages with generateMetadata (10 entity types)"
```

---

### Task 22: Migrate Tier 1 list pages (techniques, groups)

**Files:**
- Create: `app/techniques/page.tsx`
- Create: `app/groups/page.tsx`
- Modify: `src/pages/TechniquesList.tsx` — add `'use client'`, remove `usePageTitle` (already done), replace `setSearchParams`
- Modify: `src/pages/GroupsList.tsx` — same

- [ ] **Step 1: Create list pages**

```tsx
// app/techniques/page.tsx
import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { TechniquesList } from '../../src/pages/TechniquesList';

export const metadata: Metadata = {
  title: 'ATT&CK Techniques',
  description: 'Browse 800+ adversary techniques and sub-techniques across Enterprise, Mobile, ICS, and ATLAS domains with linked threat groups, software, and detection strategies',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading techniques..." />}>
      <TechniquesList />
    </Suspense>
  );
}
```

Same for groups.

- [ ] **Step 2: Rewrite `setSearchParams` in TechniquesList and GroupsList**

Replace the React Router pattern with:

```tsx
import { useSearchParams, useRouter, usePathname } from 'next/navigation';

const searchParams = useSearchParams();
const router = useRouter();
const pathname = usePathname();

// Replace every setSearchParams call:
function updateParams(updates: Record<string, string | null>) {
  const params = new URLSearchParams(searchParams.toString());
  Object.entries(updates).forEach(([k, v]) => {
    if (v === null) params.delete(k);
    else params.set(k, v);
  });
  router.push(`${pathname}?${params.toString()}`);
}
```

- [ ] **Step 3: Commit**

```bash
git add app/techniques/page.tsx app/groups/page.tsx src/pages/TechniquesList.tsx src/pages/GroupsList.tsx
git commit -m "feat: Tier 1 list pages (techniques, groups) with metadata"
```

---

## Chunk 5: Phase 2c — Tier 2 + Tier 3 Pages

### Task 23: Create all Tier 2 list pages (18 pages)

**Files:**
- Create one `app/*/page.tsx` per route (see Tier 2 table in spec)
- Modify corresponding `src/pages/*.tsx` — add `'use client'`

Each follows the same pattern — static metadata + Suspense + client component:

- [ ] **Step 1: Create all Tier 2 pages**

For each page in the Tier 2 table, create `app/[route]/page.tsx`:

```
app/software/page.tsx
app/campaigns/page.tsx
app/mitigations/page.tsx
app/tactics/page.tsx
app/sectors/page.tsx
app/applications/page.tsx
app/matrix/page.tsx
app/frameworks/owasp/page.tsx
app/frameworks/nist/page.tsx
app/frameworks/engage/page.tsx
app/frameworks/react/page.tsx
app/frameworks/veris/page.tsx
app/frameworks/cloud/page.tsx
app/frameworks/atomic/page.tsx
app/frameworks/detection/page.tsx
app/cti/cves/page.tsx
app/data-sources/page.tsx
app/external-actors/page.tsx
app/cti/reports/page.tsx
```

Each has the format:
```tsx
import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ComponentName } from '../../src/pages/ComponentFile';

export const metadata: Metadata = {
  title: 'Page Title',
  description: 'Description from spec Tier 2 table',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <ComponentName />
    </Suspense>
  );
}
```

- [ ] **Step 2: Add `'use client'` to each page component**

- [ ] **Step 3: Commit**

```bash
git add app/
git commit -m "feat: Tier 2 pages with static metadata (18 pages)"
```

---

### Task 24: Create Tier 3 pages + utility pages

**Files:**
- Create: `app/search/page.tsx`
- Create: `app/cti/feed-status/page.tsx`
- Create: `app/cti/iocs/page.tsx`
- Create: `app/cti/sigma/page.tsx`
- Create: `app/relationships/page.tsx` (redirect to /)

- [ ] **Step 1: Create Tier 3 pages**

Same pattern as Tier 2 but with minimal metadata.

- [ ] **Step 2: Create relationships redirect**

```tsx
// app/relationships/page.tsx
import { redirect } from 'next/navigation';

export default function Page() {
  redirect('/');
}
```

- [ ] **Step 3: Commit**

```bash
git add app/search/ app/cti/ app/relationships/
git commit -m "feat: Tier 3 pages + /relationships redirect"
```

---

### Task 25: Rewrite setSearchParams in all 19 page files

**Files:**
- Modify: 19 page files (17 from spec + DataSourcesList + CampaignsList confirmed by grep)

- [ ] **Step 1: Create shared `updateParams` utility**

```ts
// src/hooks/useUpdateParams.ts
'use client';

import { useSearchParams, useRouter, usePathname } from 'next/navigation';
import { useCallback } from 'react';

export function useUpdateParams() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();

  return useCallback(
    (updates: Record<string, string | null>) => {
      const params = new URLSearchParams(searchParams.toString());
      Object.entries(updates).forEach(([k, v]) => {
        if (v === null) params.delete(k);
        else params.set(k, v);
      });
      const qs = params.toString();
      router.push(qs ? `${pathname}?${qs}` : pathname);
    },
    [searchParams, router, pathname],
  );
}
```

- [ ] **Step 2: Replace `setSearchParams` in each of the 19 pages**

For each file:
1. Remove `import { useSearchParams } from 'react-router-dom'`
2. Add `import { useSearchParams } from 'next/navigation'`
3. Add `import { useUpdateParams } from '../hooks/useUpdateParams'`
4. Replace `const [searchParams, setSearchParams] = useSearchParams()` → `const searchParams = useSearchParams(); const updateParams = useUpdateParams();`
5. Replace each `setSearchParams(fn)` call with `updateParams({ key: value })`

Files (19): `Relationships.tsx`, `Search.tsx`, `CvesList.tsx`, `IocsList.tsx`, `ApplicationsList.tsx`, `TechniquesList.tsx` (done), `DetectionStrategies.tsx`, `ReportsList.tsx`, `SigmaList.tsx`, `AtomicTests.tsx`, `SoftwareList.tsx`, `ReactActions.tsx`, `NistControls.tsx`, `MitigationsList.tsx`, `GroupsList.tsx` (done), `ExternalActors.tsx`, `EngageActivities.tsx`, `DataSourcesList.tsx`, `CampaignsList.tsx`

- [ ] **Step 3: Verify — no remaining `setSearchParams` references**

```bash
grep -rn "setSearchParams" src/pages/
# Should return 0 results
```

- [ ] **Step 4: Commit**

```bash
git add src/hooks/useUpdateParams.ts src/pages/
git commit -m "feat: replace setSearchParams with useUpdateParams across 17 pages"
```

---

### Task 26: Replace all remaining react-router-dom imports

**Files:**
- Modify: all files still importing from `react-router-dom`

- [ ] **Step 1: Find remaining imports**

```bash
grep -rn "from 'react-router-dom'" src/ --include="*.tsx" --include="*.ts"
```

- [ ] **Step 2: Replace each one**

- `useNavigate` → `useRouter` from `next/navigation`
- `useParams` → `useParams` from `next/navigation`
- `useSearchParams` → `useSearchParams` from `next/navigation`
- `useLocation` → `usePathname` from `next/navigation`
- `Link` → `Link` from `next/link` (prop `to` → `href`)

- [ ] **Step 3: Verify — zero remaining**

```bash
grep -rn "react-router-dom" src/
# Should return 0
```

- [ ] **Step 4: Uninstall react-router-dom**

```bash
npm uninstall react-router-dom
```

- [ ] **Step 5: Commit**

```bash
git add -u
git add package.json package-lock.json
git commit -m "feat: remove all react-router-dom imports, uninstall package"
```

---

## Chunk 6: Phase 3 — Cleanup + Verification

### Task 27: Delete obsolete files

**Files:**
- Delete: `src/App.tsx`
- Delete: `src/main.tsx`
- Delete: `index.html`
- Delete: `server/dev-server.ts`
- Delete: entire `api/` directory (old serverless functions)

- [ ] **Step 1: Delete files**

```bash
rm src/App.tsx src/main.tsx index.html
rm -rf server/
rm -rf api/
```

- [ ] **Step 2: Verify build**

```bash
npm run build
```

Expected: Next.js build succeeds. Fix any remaining import errors.

- [ ] **Step 3: Commit**

```bash
git add -u
git commit -m "cleanup: delete App.tsx, main.tsx, index.html, server/, old api/"
```

---

### Task 28: Add prefetch={false} to high-density link pages

**Files:**
- Modify: `src/components/matrix/MatrixGrid.tsx`
- Modify: `src/pages/TechniquesList.tsx`
- Modify: `src/components/shared/EntityLink.tsx`

- [ ] **Step 1: Add `prefetch={false}` to Link components in dense listings**

In `MatrixGrid.tsx` and `TechniquesList.tsx`, find all `<Link>` components and add `prefetch={false}`.

In `EntityLink.tsx`, add `prefetch={false}` to the main `<Link>` since entity links appear in high volume across the app.

- [ ] **Step 2: Commit**

```bash
git add src/components/matrix/MatrixGrid.tsx src/pages/TechniquesList.tsx src/components/shared/EntityLink.tsx
git commit -m "perf: disable link prefetch on high-density pages"
```

---

### Task 29: Final verification

- [ ] **Step 1: Build**

```bash
npm run build
```

- [ ] **Step 2: Verify zero react-router-dom references**

```bash
grep -rn "react-router-dom" src/ app/
# Should return 0
```

- [ ] **Step 3: Verify all routes work locally**

```bash
npm run start
# Spot-check:
# / — 360 Views
# /dashboard
# /matrix
# /techniques — list
# /techniques/T1059 — detail with SSR title
# /groups/G0016 — detail
# /cti/cves — list
# /cti/cves/CVE-2024-1234 — detail
# /frameworks/owasp — list
# /api/v1/dashboard — API
# /api/a2a — A2A (POST)
# /sitemap.xml
# /robots.txt
# /relationships — redirects to /
# /nonexistent — 404 page
```

- [ ] **Step 4: View source — check SSR**

```bash
curl -s http://localhost:3000/techniques/T1059 | grep "<title>"
# Should show: <title>T1059 Command and Scripting Interpreter — MITRE Explorer</title>
```

- [ ] **Step 5: Deploy preview**

```bash
git push origin nextjs-migration
# Create preview deployment on Vercel
```

- [ ] **Step 6: Submit sitemap to Google Search Console**

Once preview is verified, merge to main, then submit `https://mitre-explorer.org/sitemap.xml` in Google Search Console.

- [ ] **Step 7: Final commit**

```bash
git commit -m "feat: Next.js migration complete — Phase 3 verified"
git tag nextjs-migration-complete
```

---

## Unresolved Questions

1. Exact SQL queries for `app/lib/data.ts` — copy from each `api/v1/*/[attackId].ts` detail endpoint during implementation
2. OWASP page split — does `OwaspTop10.tsx` need refactoring into a shared client component, or can both `page.tsx` files render it as-is with `useParams` from `next/navigation`?
3. `DataSourcesList.tsx` and `CampaignsList.tsx` — verify if they use `setSearchParams` setter or just the reader
4. Bundle size baseline — run `npx @next/bundle-analyzer` after Phase 0 to establish baseline
5. Vercel preview deployment — does the `POSTGRES_URL` env var need to be configured for preview branches?
