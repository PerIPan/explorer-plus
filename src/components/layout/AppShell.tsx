'use client';

import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTheme } from '../../contexts/ThemeContext';
import { Sidebar } from './Sidebar';
import { SearchBar } from './SearchBar';
import { RelationshipModel } from '../relationships/RelationshipModel';

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

/** Public REST API reference — rendered in the info modal's "API" tab.
 *  Documents the open, keyless /api/v1 surface that already powers the site. */
const API_GROUPS: { label: string; routes: { path: string; desc: string }[] }[] = [
  {
    label: 'ATT&CK core',
    routes: [
      { path: '/techniques', desc: 'list + filter techniques (domain, tactic, platform, search)' },
      { path: '/techniques/{attackId}', desc: 'full technique detail' },
      { path: '/tactics', desc: 'kill-chain tactics' },
      { path: '/software', desc: 'malware + tools' },
      { path: '/mitigations', desc: 'countermeasures' },
      { path: '/data-sources', desc: 'detection data sources' },
      { path: '/matrix', desc: 'tactic × technique matrix' },
    ],
  },
  {
    label: 'Threat actors',
    routes: [
      { path: '/groups', desc: 'ATT&CK threat groups' },
      { path: '/groups/{attackId}', desc: 'group profile — techniques, software, campaigns, sectors' },
      { path: '/campaigns', desc: 'named intrusion campaigns' },
      { path: '/external-actors', desc: '500+ ThaiCERT / ETDA actors' },
      { path: '/sectors', desc: 'targeted industry sectors' },
    ],
  },
  {
    label: 'Vulnerabilities & advisories',
    routes: [
      { path: '/cves', desc: 'CVEs — CVSS, EPSS, KEV, CWE (filter by severity, date)' },
      { path: '/cves/{cveId}', desc: 'CVE detail + linked techniques + advisories' },
      { path: '/advisories', desc: 'unified GHSA + OSV advisory list' },
      { path: '/ghsa/{ghsaId}', desc: 'GitHub Security Advisory detail' },
      { path: '/packages', desc: 'OSS / distro packages' },
      { path: '/ecosystems', desc: 'per-ecosystem advisory dashboards' },
      { path: '/capec', desc: 'CAPEC attack patterns' },
    ],
  },
  {
    label: 'Frameworks & compliance',
    routes: [
      { path: '/frameworks/owasp', desc: 'OWASP Top 10 (web / ML / LLM)' },
      { path: '/frameworks/csf', desc: 'NIST CSF v2 subcategories' },
      { path: '/frameworks/nist', desc: 'NIST 800-53 controls' },
      { path: '/frameworks/iso27001', desc: 'ISO/IEC 27001:2022 (via CSF crosswalk)' },
      { path: '/compliance/frameworks', desc: 'SCF-bridged frameworks (NIS2, DORA, PCI, ...)' },
      { path: '/compliance/frameworks/{key}', desc: 'framework → ATT&CK technique detail' },
    ],
  },
  {
    label: 'CTI feeds & search',
    routes: [
      { path: '/cves?severity=CRITICAL', desc: '— example: filtered query' },
      { path: '/feed/reports', desc: 'CTI reports (OTX, DFIR, Unit42, ...)' },
      { path: '/feed/iocs', desc: 'IOCs — IPs, domains, hashes, URLs' },
      { path: '/feed/sigma', desc: 'Sigma detection rules' },
      { path: '/feed/atomic', desc: 'Atomic Red Team tests' },
      { path: '/search?q=', desc: 'cross-domain entity search' },
      { path: '/dashboard', desc: 'aggregate stats' },
    ],
  },
];

/** Agent2Agent (A2A) tab — how AI agents query the knowledge base programmatically. */
function AgentToAgent() {
  return (
    <div className="px-6 py-5 space-y-4 text-sm text-[var(--text-primary)] leading-relaxed">
      <p>
        <strong>Agent2Agent (A2A) protocol.</strong> AI agents can query this knowledge base
        programmatically — discover the available skills, call them, and get back structured
        threat-intel. Open and keyless; powered by Gemini function-calling.
      </p>

      <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3 font-mono text-xs space-y-1">
        <div><span className="text-[var(--text-secondary)]">Agent Card</span>{'  '}
          <a href="/.well-known/agent-card.json" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">/.well-known/agent-card.json</a>
        </div>
        <div><span className="text-[var(--text-secondary)]">Endpoint{'  '}</span>{'  '}POST /api/a2a</div>
        <div><span className="text-[var(--text-secondary)]">Skills{'    '}</span>{'  '}25 skills · 39 tools</div>
        <div><span className="text-[var(--text-secondary)]">Limit{'     '}</span>{'  '}50 requests/day per IP · no auth</div>
        <div><span className="text-[var(--text-secondary)]">Protocol{'  '}</span>{'  '}A2A (JSON-RPC) · Gemini function-calling</div>
      </div>

      <p className="text-xs text-[var(--text-secondary)]">
        Agents fetch the Agent Card to learn the skills (CVE lookup, technique intelligence,
        threat-group profiles, advisories, CAPEC, compliance frameworks, …), then issue a
        natural-language request. The agent chains the right tools and returns a structured
        result + a rendered summary.
      </p>

      {/* Example prompt */}
      <div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-1">Example</div>
        <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3 text-xs italic text-[var(--text-secondary)]">
          &ldquo;Ask mitre-explorer.org, using the A2A protocol: <span className="not-italic text-[var(--text-primary)]">which Applications have been affected by new CVEs published in the previous week? Show the relevant ATT&amp;CK techniques, plus the latest 2-day threat reports. Render the result for me.</span>&rdquo;
        </div>
      </div>

      <p className="text-[11px] text-[var(--text-secondary)]">
        Build agent-facing apps with the latest Claude or Gemini models. The Agent Card is the
        machine-readable contract — point any A2A-capable agent at it.
      </p>
    </div>
  );
}

function ApiReference() {
  return (
    <div className="px-6 py-5 space-y-4 text-sm text-[var(--text-primary)] leading-relaxed">
      <p>
        <strong>Open REST API.</strong> Every page on this site is backed by a public, keyless JSON API —
        you can query the same data directly. No auth, no sign-up, open CORS.
      </p>
      <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3 font-mono text-xs space-y-1">
        <div><span className="text-[var(--text-secondary)]">Base URL</span>{'  '}<span className="text-[var(--accent-teal)]">https://mitre-explorer.org/api/v1</span></div>
        <div><span className="text-[var(--text-secondary)]">Format{'   '}</span>{'  '}JSON · open CORS · cache-friendly (CDN-cached)</div>
        <div><span className="text-[var(--text-secondary)]">Auth{'     '}</span>{'  '}none — keyless</div>
      </div>

      <p className="text-xs text-[var(--text-secondary)]">
        Lists return <code className="text-[var(--accent-teal)]">{`{ data: [...], pagination: {...} }`}</code>;
        detail routes return the entity object. Paginate with <code>page</code> + <code>limit</code>; filter with query params.
      </p>

      {/* curl examples */}
      <div className="rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] px-4 py-3 font-mono text-[11px] space-y-1.5 overflow-x-auto">
        <div className="text-[var(--text-secondary)]"># technique detail</div>
        <div>curl https://mitre-explorer.org/api/v1/techniques/T1059</div>
        <div className="text-[var(--text-secondary)] pt-1"># critical CVEs, newest first</div>
        <div>curl &apos;https://mitre-explorer.org/api/v1/cves?severity=CRITICAL&amp;limit=5&apos;</div>
        <div className="text-[var(--text-secondary)] pt-1"># cross-domain search</div>
        <div>curl &apos;https://mitre-explorer.org/api/v1/search?q=lazarus&apos;</div>
      </div>

      {/* endpoint groups */}
      <div className="space-y-3">
        {API_GROUPS.map((g) => (
          <div key={g.label}>
            <div className="text-[11px] font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-1">{g.label}</div>
            <ul className="space-y-0.5">
              {g.routes.map((r) => (
                <li key={r.path} className="flex flex-wrap items-baseline gap-x-2 text-xs">
                  <code className="font-mono text-[var(--text-primary)]">{r.path}</code>
                  <span className="text-[var(--text-secondary)]">{r.desc}</span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      <p className="text-xs text-[var(--text-secondary)] pt-2 border-t border-[var(--border-color)]">
        <strong className="text-[var(--text-primary)]">Fair use.</strong> Open and unmetered for normal use; heavy automated
        traffic is rate-limited per IP at the edge. For programmatic AI-agent access use the{' '}
        <a href="/.well-known/agent-card.json" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">A2A Agent Card</a>{' '}
        (50 req/day). Bulk users: contact us for a static data dump rather than crawling.
      </p>
    </div>
  );
}

/** Root layout shell — sidebar + top bar + page content */
export function AppShell({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);
  const [helpTab, setHelpTab] = useState<'about' | 'api' | 'a2a'>('about');

  return (
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
          <SearchBar />
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
            mitre-explorer.org
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
              </div>
              <button onClick={() => setHelpOpen(false)} className="p-2 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            {helpTab === 'api' && <ApiReference />}
            {helpTab === 'a2a' && <AgentToAgent />}
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
<li><strong>Agent2Agent (A2A) protocol</strong> — AI agents can query this knowledge base programmatically. See the <strong>Agent2Agent</strong> tab.</li>
                <li><strong>Actor comparison</strong> — select up to 3 threat actors on the Matrix, see technique overlap color-coded, export as HTML</li>
                <li><strong>360 Views</strong> — search any entity, explore via Technique Map, Actor Profile, Malware Map, Application Map, Sector Map, or D3 force graph</li>
                <li><strong>Applications</strong> — 11K+ vendor products linked to CVEs → CWE → CAPEC → ATT&CK techniques → threat groups. See which apps your adversaries target</li>
                <li><strong>Advisories</strong> — unified GHSA (OSS packages) + OSV (Linux kernel, Debian, Ubuntu, Alpine, Android, Red Hat, SUSE, Rocky, Alma, Chainguard, OSS-Fuzz …) with faceted filters — severity, ecosystem category, CVE-alias</li>
                <li><strong>CVEs</strong> — since 2017, CISA KEV + NVD CVSS enrichment + EPSS exploit-probability scoring (First.org, daily), linked to ATT&CK via CWE→CAPEC bridge + CTID mappings, cross-referenced to distro advisories</li>
                <li><strong>Frameworks</strong> — OWASP Top 10 (Web 2021, ML 2023, LLM 2025), NIST 800-53 r5, NIST CSF v2 (GV/ID/PR/DE/RS/RC with CRI Profile crosswalk), MITRE Engage, D3FEND, RE&CT, VERIS, ISO/IEC 27001:2022, AWS + Azure + GCP cloud controls, CAPEC (615 patterns, full taxonomy), EU Cyber Resilience Act reference</li>
                <li><strong>IOCs</strong> — OTX + ThreatFox + MalwareBazaar, enriched with VirusTotal verdicts and sandbox-derived techniques</li>
                <li><strong>Detection</strong> — Detection Strategies + Analytics (ATT&CK v19), SigmaHQ rules, Atomic Red Team tests, MITRE Caldera, D3FEND countermeasures</li>
                <li><strong>Threat actors</strong> — 191 ATT&CK groups + 514 ThaiCERT/ETDA actors with category inference</li>
                <li><strong>Compliance</strong> — regulatory + audit frameworks (NIS2, DORA, PCI DSS, NIST 800-53, HIPAA, GDPR, CMMC, ...) bridged to ATT&CK via the Secure Controls Framework (SCF)</li>
                <li><strong>Data model</strong> — 30+ interconnected data sources: ATT&CK STIX, ATLAS, CVElistV5, NVD, CAPEC, CWE, NIST 800-53, NIST CSF v2, CISA KEV, EPSS, OTX, SigmaHQ, Atomic Red Team, D3FEND, VERIS, CTID, GHSA, OSV, SCF</li>
                <li><strong>Sector + domain filters</strong> — narrow everything by industry and ATT&CK domain (AND logic)</li>
                <li><strong>Diamond Model</strong> — Adversary (Threat Actors) | Victim (Sectors) | Infrastructure (Applications) | Capability (Techniques)</li>
              </ul>
              <p className="text-[var(--text-secondary)] text-xs pt-2 border-t border-[var(--border-color)]">
                <span className="text-[var(--accent-teal)]">contact @ mitre-explorer.org</span>
                {' · '}<a href="/about/attributions" className="text-[var(--accent-teal)] hover:underline">Data attributions</a>
                {' — '}Not affiliated with or endorsed by MITRE Corporation.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
