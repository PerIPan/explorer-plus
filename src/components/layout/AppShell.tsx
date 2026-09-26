'use client';

import { Suspense, lazy, useEffect, useRef, useState } from 'react';
import { usePathname } from 'next/navigation';
import { AGENT_TOOL_COUNT, SITE_URL } from '../../lib/site';
import { track } from '@vercel/analytics';
import { useQuery } from '@tanstack/react-query';
import { useTheme } from '../../contexts/ThemeContext';
import { Sidebar } from './Sidebar';
import { ThreatProfileProvider, ProfileLargeModal } from '../profile/ProfilePanel';
import { SearchBar } from './SearchBar';
import { RelationshipModel } from '../relationships/RelationshipModel';
import { Dialog, DialogTab } from '../shared/Dialog';

interface SiteHealth {
  available: boolean;
  malicious?: number;
  total?: number;
  reportUrl?: string;
}

/** VirusTotal trust badge */
function VtBadge() {
  const { data } = useQuery({
    queryKey: ['site-health'],
    queryFn: async (): Promise<SiteHealth> => {
      const r = await fetch('/api/v1/site-health');
      return r.ok ? r.json() : { available: false };
    },
    staleTime: 5 * 60 * 1000,
    retry: 1,
  });
  if (!data?.available || data.malicious == null || data.total == null || !data.reportUrl) return null;
  return (
    <a
      href={data.reportUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1 text-[10px] rounded-md border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 hover:border-emerald-400 transition-colors"
      title={`VirusTotal: ${data.malicious}/${data.total} detections — click to view full report`}
    >
      <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      {data.malicious}/{data.total}
    </a>
  );
}

/** Theme toggle — sun/moon icon */
function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      data-print-hide
      className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
      ) : (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      )}
    </button>
  );
}

/**
 * The API / A2A / MCP prose, loaded on demand.
 *
 * It used to live here as four components over a hand-written `API_GROUPS` array
 * — 55 documented paths against 86 real routes, with the origin hardcoded six
 * times. It now renders `src/lib/api-catalog.ts`, the one catalogue that
 * /open-apis and /open-mcp also read, and `scripts/check-api-catalog.mjs` fails
 * the build if that catalogue and the route tree disagree.
 *
 * LAZY on purpose: AppShell is in the chunk every page loads, and a static
 * import would put the whole catalogue there for a modal most visitors never
 * open. The cost lands when the panel does.
 */
const ApiCatalogPanel = lazy(() =>
  import('../api/ApiCatalogPanel').then((m) => ({ default: m.ApiCatalogPanel })),
);

function ApiPanel({ tab }: { tab: 'rest' | 'mcp' | 'a2a' }) {
  return (
    <Suspense
      fallback={<div className="px-6 py-8 text-xs text-[var(--text-secondary)]">Loading the catalogue…</div>}
    >
      <ApiCatalogPanel tab={tab} />
    </Suspense>
  );
}

/** Host without the scheme, for the print watermark and the contact line. */
const SITE_HOST = SITE_URL.replace(/^https?:\/\//, '');

/** Root layout shell — sidebar + top bar + page content */
export function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  /* The info modal is hand-rolled (no Dialog, so no useDialog contract) and
     AppShell is in the root layout, so it too survived a route change while the
     API panel inside it links to /open-apis. Closing on navigation is the half
     of the fix that matters to a reader; the full port to <Dialog> — role,
     trap, Escape — is still outstanding. */
  const helpPathname = usePathname();
  useEffect(() => setHelpOpen(false), [helpPathname]);
  const [helpTab, setHelpTab] = useState<'about' | 'api' | 'a2a' | 'mcp'>('about');
  const [apisOpen, setApisOpen] = useState(false);
  const [apisTab, setApisTab] = useState<'rest' | 'mcp' | 'a2a'>('rest');
  /** Focus goes back here when the APIs dialog closes. */
  const apisButtonRef = useRef<HTMLButtonElement | null>(null);

  return (
    /* The Threat Profile controller lives here, not on the homepage, so the
       sidebar's "Threat Profile" entry can open the same questions on ANY
       page. Mounting the provider is availability only: it arms no timer and
       posts no telemetry. The unsolicited peek is still homepage-only — it is
       armed by `ProfilePeekArmer`, which renders exclusively in the homepage
       landing state next to the diamonds (src/views/Relationships.tsx). */
    <ThreatProfileProvider variant="v1-4q">
    <div className="flex min-h-screen bg-[var(--surface-deep)]">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main area pushed right of the fixed sidebar on lg+ */}
      <div className="flex-1 flex flex-col lg:ml-52 min-h-screen min-w-0">
        {/* Top header bar */}
        <header className="sticky top-0 z-30 flex items-center gap-2 md:gap-4 px-3 md:px-6 py-2 md:py-3 bg-[var(--surface-card)] shadow-sm border-b border-[var(--border-color)]">
          {/* Hamburger — visible only below lg */}
          <button
            type="button"
            aria-label="Open navigation menu"
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden flex-shrink-0 p-1 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          {/* min-w-0 lets the search input shrink instead of forcing the row
              wider than the viewport — the header has no flex-wrap and the
              APIs / MCP button next to it must stay reachable. */}
          <div className="flex-1 min-w-0">
            <SearchBar />
          </div>
          <button
            type="button"
            ref={apisButtonRef}
            onClick={() => {
              track('apis_open');
              setApisOpen(true);
            }}
            data-print-hide
            className="flex-shrink-0 px-3 h-8 inline-flex items-center justify-center rounded-md border border-[var(--border-color)] text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="Open REST API and MCP server — full endpoint catalog"
          >
            APIs / MCP
          </button>
          <button
            type="button"
            onClick={() => setModelOpen(true)}
            className="hidden flex-shrink-0 px-3 py-1.5 text-xs rounded-md border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="ATT&CK data model — entity relationships"
          >
            Data Model
          </button>
          <div className="flex-1" />
          <div className="hidden md:block"><VtBadge /></div>
          <ThemeToggle />
          <button
            type="button"
            onClick={() => setHelpOpen(true)}
            data-print-hide
            className="flex-shrink-0 px-3 h-8 inline-flex items-center justify-center rounded-md border border-[var(--border-color)] text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="About this application"
          >
            info
          </button>
        </header>

        {/* Page content */}
        <main className="flex-1 px-3 md:px-6 py-4 md:py-6 overflow-y-auto overflow-x-hidden">
          {children}
        </main>

        {/* Print-only watermark — bottom right */}
        <div className="print-watermark hidden fixed bottom-4 right-6 items-center gap-2 opacity-60" style={{ zIndex: 9999 }}>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="18" height="18">
            <g transform="translate(16,16) rotate(45) translate(-11,-11)">
              <rect x="0" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.6"/>
              <rect x="11.2" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.75"/>
              <rect x="11.2" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="0.88"/>
              <rect x="0" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="1"/>
            </g>
          </svg>
          <span style={{ fontSize: '10px', color: '#64748b', fontWeight: 600, letterSpacing: '0.03em' }}>
            {SITE_HOST}
          </span>
        </div>
      </div>

      <RelationshipModel open={modelOpen} onClose={() => setModelOpen(false)} />

      {/* Help modal */}
      {helpOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setHelpOpen(false)}>
          <div
            className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-xl shadow-2xl w-[95vw] max-w-[640px] max-h-[85vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)]">
              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={() => setHelpTab('about')}
                  className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors ${helpTab === 'about' ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
                >
                  About
                </button>
                <button
                  type="button"
                  onClick={() => setHelpTab('api')}
                  className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors ${helpTab === 'api' ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
                >
                  API
                </button>
                <button
                  type="button"
                  onClick={() => setHelpTab('a2a')}
                  className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors ${helpTab === 'a2a' ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
                >
                  Agent2Agent
                </button>
                <button
                  type="button"
                  onClick={() => setHelpTab('mcp')}
                  className={`px-3 py-1.5 text-sm font-semibold rounded-md transition-colors ${helpTab === 'mcp' ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)]' : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]'}`}
                >
                  MCP
                </button>
              </div>
              <button onClick={() => setHelpOpen(false)} className="p-2 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {/* The same panel the APIs / MCP modal renders — one catalogue, one copy
                of every connection fact. */}
            {helpTab === 'api' && <ApiPanel tab="rest" />}
            {helpTab === 'a2a' && <ApiPanel tab="a2a" />}
            {helpTab === 'mcp' && <ApiPanel tab="mcp" />}
            <div className={`px-6 py-5 space-y-4 text-sm text-[var(--text-primary)] leading-relaxed ${helpTab === 'about' ? '' : 'hidden'}`}>
              <div className="flex justify-center pb-2">
                <img src="/diamond-favicon.svg" alt="MITRE Explorer Plus" className="w-12 h-12" />
              </div>
              <p>
                <strong>MITRE Explorer Plus</strong> — a multi-domain threat intelligence platform on{' '}
                <em>MITRE ATT&CK</em>. Single interface for adversary behavior, detection, compliance, and application security — enriched with CTI reports, CVE vulnerabilities, and open-source + distro advisories.
              </p>
              <ul className="space-y-2 pl-4 list-disc marker:text-[var(--accent-teal)]">
                <li><strong>Multi-domain ATT&CK + ATLAS</strong> — Enterprise, ICS, Mobile, ATLAS (AI/ML threats) with domain switcher + "All Domains" cross-domain view</li>
                <li><strong>ICS / OT</strong> — 18 ATT&CK for ICS assets (PLCs, RTUs, HMIs, historians, safety controllers, jump hosts) with the techniques that target each, placed on the <strong>Purdue model</strong>: seven levels from the physical process to enterprise IT, the industrial DMZ between them, and which levels are allowed to communicate — each asset also showing the D3FEND countermeasures that defend it</li>
<li><strong>Agent2Agent (A2A) protocol</strong> — AI agents can query this knowledge base programmatically. See the <strong>Agent2Agent</strong> tab.</li>
                <li><strong>MCP server</strong> — point Claude, Cursor or any MCP client at <code>/api/mcp</code> and query all of the above in conversation: {AGENT_TOOL_COUNT} tools over Streamable HTTP, anonymous and unmetered. See the <strong>APIs / MCP</strong> button in the top bar.</li>
                <li><strong>Actor comparison</strong> — select up to 3 threat actors on the Matrix, see technique overlap color-coded, export as HTML</li>
                <li><strong>360 Views</strong> — search any entity, explore via Threat Actor Profile, Technique Map, Malware Map, Mitigation Map, Data Source Map, Tactic Map, Sector Map, Application Map, Asset Map, OWASP Map, or D3 force graph</li>
                <li><strong>Applications</strong> — 19K+ vendor products linked to CVEs → CWE → CAPEC → ATT&CK techniques → threat groups. See which apps your adversaries target</li>
                <li><strong>Advisories</strong> — unified GHSA (OSS packages) + OSV (Linux kernel, Debian, Ubuntu, Alpine, Android, Red Hat, SUSE, Rocky, Alma, Chainguard, OSS-Fuzz …) with faceted filters — severity, ecosystem category, CVE-alias</li>
                <li><strong>CVEs</strong> — since 2017, CISA KEV + NVD CVSS enrichment + EPSS exploit-probability scoring (First.org, daily), linked to ATT&CK via CWE→CAPEC bridge + CTID mappings, cross-referenced to distro advisories</li>
                <li><strong>Frameworks</strong> — OWASP Top 10 (Web 2021, ML 2023, LLM 2025), NIST 800-53 r5, NIST CSF v2 (GV/ID/PR/DE/RS/RC with CRI Profile crosswalk), MITRE Engage, D3FEND (153 countermeasures across seven defensive tactics), RE&CT, VERIS, ISO/IEC 27001:2022, AWS + Azure + GCP cloud controls, CAPEC (615 patterns, full taxonomy), Purdue model (OT network segmentation), EU Cyber Resilience Act reference</li>
                <li><strong>IOCs</strong> — OTX + ThreatFox + MalwareBazaar, enriched with VirusTotal verdicts and sandbox-derived techniques</li>
                <li><strong>Detection</strong> — Detection Strategies + Analytics (ATT&CK v19), SigmaHQ rules, Atomic Red Team tests, MITRE Caldera, D3FEND countermeasures</li>
                <li><strong>Threat actors</strong> — 180 ATT&CK groups + 514 ThaiCERT/ETDA actors with category inference</li>
                <li><strong>Compliance</strong> — regulatory + audit frameworks (NIS2, DORA, PCI DSS, NIST 800-53, HIPAA, GDPR, CMMC, ...) bridged to ATT&CK via the Secure Controls Framework (SCF)</li>
                <li><strong>Data model</strong> — 30+ interconnected data sources: ATT&CK STIX (incl. the ICS asset catalogue), ATLAS, CVElistV5, NVD, CAPEC, CWE, NIST 800-53, NIST CSF v2, NIST 800-82r3 / ISA-95 (Purdue levels), CISA KEV, EPSS, OTX, SigmaHQ, Atomic Red Team, D3FEND, VERIS, CTID, GHSA, OSV, SCF</li>
                <li><strong>Sector + domain filters</strong> — narrow everything by industry and ATT&CK domain (AND logic)</li>
                <li><strong>Diamond Model</strong> — Adversary (Threat Actors) | Victim (Sectors) | Infrastructure (Applications) | Capability (Techniques)</li>
              </ul>
              <p className="text-[var(--text-secondary)] text-xs pt-2 border-t border-[var(--border-color)]">
                <span className="text-[var(--accent-teal)]">contact @ {SITE_HOST}</span>
                {' · '}<a href="/about/attributions" className="text-[var(--accent-teal)] hover:underline">Data attributions</a>
                {' — '}Not affiliated with or endorsed by MITRE Corporation.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* APIs / MCP — the shared catalogue, quick-reference role.
          Now a real dialog: role, aria-modal, focus moved in and trapped, the
          background inert, Escape, and focus handed back to the top-bar button.
          It had none of that when it owned its own endpoint list. */}
      <Dialog
        open={apisOpen}
        onClose={() => setApisOpen(false)}
        title="Open APIs · MCP · A2A"
        subtitle="Public, keyless, unmetered. Three doors onto the same data."
        returnFocusTo={apisButtonRef}
        maxWidth="820px"
        tabs={
          <>
            <DialogTab active={apisTab === 'rest'} onClick={() => setApisTab('rest')}>REST API</DialogTab>
            <DialogTab active={apisTab === 'a2a'} onClick={() => setApisTab('a2a')}>A2A</DialogTab>
            <DialogTab active={apisTab === 'mcp'} onClick={() => setApisTab('mcp')}>MCP</DialogTab>
          </>
        }
      >
        <ApiPanel tab={apisTab} />
      </Dialog>

      {/* The sidebar entry's presentation. Portals to <body>, renders only
          when the sidebar opened it, and is inert otherwise — the diamonds'
          two presentations are still mounted on the homepage. */}
      <ProfileLargeModal />
    </div>
    </ThreatProfileProvider>
  );
}
