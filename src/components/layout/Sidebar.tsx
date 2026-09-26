'use client';

import { Fragment, useState, useEffect } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { DomainDropdown } from './DomainDropdown';
import { SectorDropdown } from './SectorDropdown';
import { ProfileSidebarTrigger } from '../profile/ProfilePanel';
import { AGENT_TOOL_COUNT, API_ENDPOINT_COUNT } from '../../lib/site';
import { FEED_SOURCES } from '../../lib/feeds';


interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

interface NavItem {
  path: string;
  label: string;
  tooltip?: string;
  /** Renders the label one step heavier than its siblings (semibold vs medium). */
  emphasis?: boolean;
  /**
   * How many things the page lists, shown as `Open APIs (81)`. Only for pages
   * whose size is the reason to visit and whose count comes from a constant the
   * page itself uses — never a number typed twice.
   */
  count?: number;
}

interface NavSection {
  label?: string;
  items: NavItem[];
}

const topNav: NavItem[] = [
  { path: '/', label: '360 Views', tooltip: 'explore entity connections — graph and dedicated map views for every entity type' },
  { path: '/matrix', label: 'Matrix', tooltip: 'att&ck technique matrix heatmap — tactics vs techniques' },
  { path: '/dashboard', label: 'Overview', tooltip: 'summary stats, charts, and top threat groups' },
  { path: '/compliance', label: 'Compliance', emphasis: true, tooltip: 'regulatory and audit frameworks (NIS2, DORA, PCI DSS, NIST 800-53, HIPAA, GDPR, CMMC, ...) bridged to ATT&CK Enterprise via the Secure Controls Framework (SCF)' },
  { path: '/cti/feed-status', label: 'Feed Status', count: FEED_SOURCES.length, tooltip: 'CTI feed ingestion health and manual sync controls' },
  { path: '/open-apis', label: 'Open APIs', count: API_ENDPOINT_COUNT, tooltip: 'the public REST API behind every page here — no key, no sign-up, no rate limit. every endpoint with its parameters, and a button that calls it' },
  { path: '/open-mcp', label: 'Open MCP', count: AGENT_TOOL_COUNT, tooltip: `point claude, cursor or any MCP client at this knowledge base — ${AGENT_TOOL_COUNT} tools over streamable http, anonymous. also covers the A2A endpoint` },
];

const attackNav: NavItem[] = [
  { path: '/groups', label: 'Groups', tooltip: 'tracked threat actor groups (APT29, Lazarus, etc.)' },
  // Sectors are ATT&CK-derived (group_sectors), not a top-level concept — they
  // were in topNav until the two API entries needed that space.
  { path: '/sectors', label: 'Sectors', tooltip: 'industry sectors targeted by threat groups — click any sector for its 360 view' },
  { path: '/campaigns', label: 'Campaigns', tooltip: 'named intrusion campaigns with timelines' },
  { path: '/tactics', label: 'Tactics', tooltip: 'kill chain phases: recon → impact' },
  { path: '/techniques', label: 'Techniques', tooltip: 'attack techniques and sub-techniques used by adversaries' },
  { path: '/software', label: 'Malware', tooltip: 'attacker view — malware and tools used by threat actors (vs Applications which are victim products)' },
  { path: '/mitigations', label: 'Mitigations', tooltip: 'countermeasures to prevent or limit techniques' },
  { path: '/data-sources', label: 'Data Sources', tooltip: 'telemetry sources for detecting techniques' },
  { path: '/frameworks/detection', label: 'Detection', tooltip: 'ATT&CK v18 detection strategies and analytics' },
  { path: '/frameworks/engage', label: 'Engage', tooltip: 'adversary deception and engagement activities' },
];

const assetsNav: NavItem[] = [
  { path: '/applications', label: 'Applications', tooltip: 'defender view — vendor products that get exploited (vs Malware which is attacker tools)' },
  { path: '/assets', label: 'ICS Assets', tooltip: 'ATT&CK for ICS equipment — PLCs, RTUs, HMIs, historians, gateways — with the techniques targeting each and its Purdue level' },
  { path: '/ecosystems', label: 'Ecosystems', tooltip: 'per-ecosystem advisory dashboards — npm, PyPI, Debian, Ubuntu, Alpine, Android, Linux kernel, Chainguard, OSS-Fuzz, and more. Severity breakdowns + top affected packages' },
  { path: '/packages', label: 'Packages', tooltip: 'library/dependency packages with GHSA advisories (npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust)' },
];

const ctiNav: NavItem[] = [
  { path: '/cti/reports', label: 'Reports', tooltip: 'threat intelligence reports from OTX, RSS feeds' },
  { path: '/cti/cves', label: 'CVEs', tooltip: 'known vulnerabilities from OTX, CISA KEV, enriched via NVD' },
  { path: '/cti/advisories', label: 'Advisories', tooltip: 'unified advisories list — GHSA (OSS packages: npm/PyPI/Maven/Go/…) + OSV (OS & distros: Linux kernel, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, …). Separate detail pages per source.' },
  { path: '/cti/iocs', label: 'IOCs', tooltip: 'hashes, domains, IPs, URLs from AlienVault OTX, CISA KEV' },
];

const frameworksNav: NavItem[] = [
  { path: '/frameworks/owasp', label: 'OWASP Top 10', tooltip: 'web, ML, and LLM security risks mapped to ATT&CK + ATLAS via CWE' },
  { path: '/frameworks/csf', label: 'NIST CSF v2', tooltip: 'NIST Cybersecurity Framework v2 subcategories (GV/ID/PR/DE/RS/RC) mapped to ATT&CK techniques' },
  { path: '/frameworks/nist', label: 'NIST 800-53', tooltip: 'compliance controls mapped to techniques' },
  { path: '/frameworks/iso27001', label: 'ISO/IEC 27001:2022', tooltip: 'ISO 27001:2022 Annex A controls + mandatory clauses mapped to ATT&CK via the NIST CSF v2 crosswalk' },
  { path: '/frameworks/d3fend', label: 'D3FEND', tooltip: 'MITRE D3FEND countermeasures grouped by defensive tactic (Model/Harden/Detect/Isolate/Deceive/Evict/Restore), each mapped to the ATT&CK techniques it counters. Enterprise + ICS.' },
  { path: '/frameworks/react', label: 'RE&CT', tooltip: 'incident response actions and playbooks' },
  { path: '/frameworks/veris', label: 'VERIS', tooltip: 'incident classification categories (Verizon DBIR standard)' },
  { path: '/frameworks/cloud', label: 'Cloud Controls', tooltip: 'AWS, Azure, and GCP security controls mapped to techniques' },
  { path: '/frameworks/purdue', label: 'Purdue Model', tooltip: 'OT network segmentation — seven levels from physical process to enterprise IT, which ICS assets sit at each, and which levels may communicate' },
  { path: '/cti/sigma', label: 'Sigma Rules', tooltip: 'detection signatures mapped to techniques (SigmaHQ)' },
  { path: '/frameworks/atomic', label: 'Atomic Tests', tooltip: 'red team validation tests from Atomic Red Team' },
  { path: '/cti/capec', label: 'CAPEC', tooltip: 'MITRE Common Attack Pattern Enumeration — 615 attack patterns with severity, likelihood, prerequisites, mitigations' },
  { path: '/frameworks/cra', label: 'CRA – wip', tooltip: 'EU Cyber Resilience Act (Regulation 2024/2847) — reference page covering key dates, Annex I essential requirements, Article 14 reporting cadence. Mappings to ATT&CK/CWE pending harmonised standards.' },
  { path: '/frameworks/owasp-ai', label: 'OWASP AI – wip', tooltip: 'OWASP AI Exchange — AI/ML threats, controls, and framework alignments (ISO 27090, EU AI Act). Structured JSON/ATLAS crosswalks on the 2026 roadmap; reference page for now.' },
];

const extendedIntelNav: NavItem[] = [
  { path: '/external-actors', label: 'Non-MITRE Actors', tooltip: '500+ threat actors from ThaiCERT encyclopedia' },
];

/**
 * The shared geometry of a nav row. Pulled out so the Threat Profile entry —
 * a <button>, since it opens a modal instead of navigating — sits on exactly
 * the same grid as the links around it. `w-full text-left` is the only thing
 * a button needs on top of it to look like a block-level link.
 */
const NAV_ROW_CLASS = 'block px-3 py-2.5 rounded-md text-sm transition-colors duration-150';
const NAV_ROW_IDLE_CLASS =
  'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]';

function NavItemLink({ path, label, tooltip, end, emphasis, count }: NavItem & { end?: boolean }) {
  const pathname = usePathname();
  const isActive = end
    ? pathname === path
    : pathname === path || pathname.startsWith(path + '/');
  return (
    <Link
      href={path}
      title={tooltip}
      className={[
        NAV_ROW_CLASS,
        emphasis ? 'font-semibold' : 'font-medium',
        isActive
          ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)] border-l-2 border-[var(--accent-teal)]'
          : NAV_ROW_IDLE_CLASS,
      ].join(' ')}
    >
      {label}
      {count !== undefined && (
        <span className="ml-1 font-normal text-[var(--text-secondary)]">({count})</span>
      )}
    </Link>
  );
}

function CollapsibleNavSection({ label, items, defaultOpen = false, title }: { label: string; items: NavItem[]; defaultOpen?: boolean; title?: string }) {
  const pathname = usePathname();
  const isActiveRoute = items.some((item) => pathname.startsWith(item.path));
  const [open, setOpen] = useState(defaultOpen || isActiveRoute);

  // Collapse non-active sections on mobile after hydration
  useEffect(() => {
    if (window.innerWidth < 1024 && !isActiveRoute) setOpen(false);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-expand when navigating to a route inside this section
  useEffect(() => {
    if (isActiveRoute) setOpen(true);
  }, [isActiveRoute]);

  return (
    <div>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 w-full px-3 mb-1.5 ml-1 border-l-2 border-[var(--teal-muted)] pl-2 text-[11px] font-bold text-[var(--accent-teal)] uppercase tracking-widest hover:text-[var(--accent-teal-light)] transition-colors"
        title={title}
      >
        <svg
          className={`w-3 h-3 transition-transform duration-200 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          strokeWidth={2.5}
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
        </svg>
        {label}
      </button>
      {open && (
        <div className="space-y-0.5">
          {items.map((item) => (
            <NavItemLink key={item.path} {...item} />
          ))}
        </div>
      )}
    </div>
  );
}

export function Sidebar({ open, onClose }: SidebarProps) {
  return (
    <aside
      className={[
        'fixed top-0 left-0 h-screen w-52 bg-[var(--surface-card)] border-r border-[var(--border-color)] flex flex-col z-50 overflow-y-auto',
        'transition-transform duration-200 ease-in-out',
        open ? 'translate-x-0' : '-translate-x-full pointer-events-none lg:translate-x-0 lg:pointer-events-auto',
      ].join(' ')}
      aria-label="Main navigation"
    >
      {/* Logo / Title */}
      <div className="px-5 py-4 border-b border-[var(--border-color)] flex items-center justify-between">
        <button
          type="button"
          onClick={() => {
            // Best-effort filter reset — private mode / blocked site data
            // must not stop the logo from navigating home (see
            // ThemeContext.tsx:36-41 for the same failure mode elsewhere).
            try {
              sessionStorage.removeItem('mitre-domain');
              sessionStorage.removeItem('mitre-sector');
            } catch { /* private mode / storage disabled — navigate anyway */ }
            window.location.href = '/';
          }}
          className="group text-left"
        >
          <div className="flex items-baseline gap-1">
            <span className="text-[var(--accent-teal)] font-bold text-xs tracking-widest uppercase group-hover:text-[var(--accent-teal-light)] transition-colors">MITRE EXPLORER</span>
            <span className="text-[var(--text-secondary)] text-[10px] font-semibold group-hover:text-[var(--text-primary)] transition-colors align-super">Plus</span>
          </div>
        </button>
        {/* Close button — visible only below lg */}
        <button
          type="button"
          aria-label="Close navigation menu"
          onClick={onClose}
          className="lg:hidden p-1 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors"
        >
          <svg
            className="w-4 h-4"
            fill="none"
            stroke="currentColor"
            strokeWidth={2}
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      {/* Domain & Sector — directly under logo */}
      <div className="px-5 py-2 border-b border-[var(--border-color)] space-y-1.5">
        <DomainDropdown />
        <SectorDropdown />
      </div>

      {/* Main Nav — unlabeled top entries */}
      <nav
        className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto
          [scrollbar-width:thin] [scrollbar-color:var(--border-color)_transparent]
          [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-track]:bg-transparent
          [&::-webkit-scrollbar-thumb]:bg-[var(--border-color)] [&::-webkit-scrollbar-thumb]:rounded-full"
      >
        {topNav.map((item) => (
          <Fragment key={item.path}>
            <NavItemLink {...item} end={item.path === '/'} />
            {/* Directly after Compliance. Not a NavItem: it has no route —
                it opens the profile questions in a modal over whatever page
                you are on, and only Apply navigates (to /profile). */}
            {item.path === '/compliance' && (
              <ProfileSidebarTrigger
                // Says what the answers DO. The old wording promised that all
                // four questions "rank techniques, actors and controls", but
                // role and compliance regime are collected for context and
                // reach nothing on /profile — and "four questions" stopped
                // being true when the OT set (plant surface, role, regime)
                // shipped. Neither a count nor an unearned promise now.
                title="tailor the explorer to what you defend — an IT sector and environment, or an OT plant surface, and the briefing ranks techniques, actors and controls on that"
                className={[
                  NAV_ROW_CLASS,
                  'w-full text-left font-medium',
                  NAV_ROW_IDLE_CLASS,
                  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-teal)]',
                ].join(' ')}
              />
            )}
          </Fragment>
        ))}
      </nav>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* Assets Section */}
      <div className="px-2 py-3">
        <CollapsibleNavSection label="Assets" items={assetsNav} />
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* CTI Section */}
      <div className="px-2 py-3">
        <CollapsibleNavSection label="CTI" items={ctiNav} />
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* Frameworks Section */}
      <div className="px-2 py-3">
        <CollapsibleNavSection label="Frameworks" items={frameworksNav} defaultOpen={false} title="Not filtered by sector" />
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* ATT&CK Section — groups + campaigns + offensive/defensive taxonomy */}
      <div className="px-2 py-3">
        <CollapsibleNavSection label="ATT&CK" items={attackNav} />
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* Extended Intel Section */}
      <div className="px-2 py-3">
        <CollapsibleNavSection label="Extended Intel" items={extendedIntelNav} defaultOpen={false} />
      </div>

      {/* Agent access — A2A + MCP both serve the same tool catalogue */}
      <div className="mt-auto px-4 py-3 border-t border-[var(--border-color)] space-y-0.5">
        <a
          href="/.well-known/agent-card.json"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-2 py-1.5 rounded-md text-[10px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:bg-[var(--hover-overlay)] transition-colors"
          title="A2A Agent-to-Agent Protocol — AI agents can query this knowledge base programmatically"
        >
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="4" cy="8" r="2.5" />
            <circle cx="12" cy="8" r="2.5" />
            <path d="M6.5 8h3" />
          </svg>
          <span>A2A Agent Protocol</span>
          <span className="ml-auto text-[9px] opacity-50">v1.0</span>
        </a>
        {/* Deliberately NOT a link to /api/mcp: that endpoint is POST-only and
            answers GET with a raw 405 JSON-RPC blob. It used to open the info
            modal's MCP tab; /open-mcp is the page that tab was standing in for. */}
        <Link
          href="/open-mcp"
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-[10px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:bg-[var(--hover-overlay)] transition-colors text-left"
          title="MCP server — connect Claude, Cursor or any MCP client. Setup, every tool, and the A2A endpoint."
        >
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M2 11.5 7 6.5a2 2 0 0 1 2.8 0L11 7.7" />
            <path d="M5 11.5 9.2 7.3a2 2 0 0 1 2.8 0l2 2" />
            <path d="M8 14l5.5-5.5" />
          </svg>
          <span>MCP Server</span>
          <svg viewBox="0 0 16 16" width="11" height="11" fill="none" stroke="currentColor" strokeWidth="1.5" className="ml-auto opacity-60" aria-hidden="true">
            <path d="M6 3.5 10.5 8 6 12.5" />
          </svg>
        </Link>
      </div>
    </aside>
  );
}
