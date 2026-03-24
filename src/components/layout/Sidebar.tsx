import { useState, useEffect } from 'react';
import { NavLink, Link, useLocation } from 'react-router-dom';
import { DomainDropdown } from './DomainDropdown';
import { SectorDropdown } from './SectorDropdown';

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

interface NavItem {
  path: string;
  label: string;
  tooltip?: string;
}

interface NavSection {
  label?: string;
  items: NavItem[];
}

const mainSections: NavSection[] = [
  {
    items: [
      { path: '/', label: 'Relationships', tooltip: 'explore entity connections — graph and dedicated map views for every entity type' },
      { path: '/matrix', label: 'Matrix', tooltip: 'att&ck technique matrix heatmap — tactics vs techniques' },
      { path: '/dashboard', label: 'Overview', tooltip: 'summary stats, charts, and top threat groups' },
    ],
  },
  {
    label: 'Threat Actors',
    items: [
      { path: '/groups', label: 'Groups', tooltip: 'tracked threat actor groups (APT29, Lazarus, etc.)' },
      { path: '/campaigns', label: 'Campaigns', tooltip: 'named intrusion campaigns with timelines' },
      { path: '/sectors', label: 'Sectors', tooltip: 'industry sectors targeted by threat groups' },
    ],
  },
  {
    label: 'Offensive',
    items: [
      { path: '/tactics', label: 'Tactics', tooltip: 'kill chain phases: recon → impact' },
      { path: '/techniques', label: 'Techniques', tooltip: 'attack techniques and sub-techniques used by adversaries' },
      { path: '/software', label: 'Software', tooltip: 'malware and tools used by threat actors' },
    ],
  },
  {
    label: 'Defensive',
    items: [
      { path: '/mitigations', label: 'Mitigations', tooltip: 'countermeasures to prevent or limit techniques' },
      { path: '/data-sources', label: 'Data Sources', tooltip: 'telemetry sources for detecting techniques' },
    ],
  },
];

const ctiNav: NavItem[] = [
  { path: '/cti/reports', label: 'Reports', tooltip: 'threat intelligence reports from OTX, RSS feeds' },
  { path: '/cti/cves', label: 'CVEs', tooltip: 'known vulnerabilities from OTX, CISA KEV, enriched via NVD' },
  { path: '/cti/iocs', label: 'IOCs', tooltip: 'hashes, domains, IPs, URLs from AlienVault OTX, CISA KEV' },
  { path: '/cti/feed-status', label: 'Feed Status', tooltip: 'CTI feed ingestion health and manual sync controls' },
];

const frameworksNav: NavItem[] = [
  { path: '/frameworks/nist', label: 'NIST 800-53', tooltip: 'compliance controls mapped to techniques' },
  { path: '/frameworks/engage', label: 'Engage', tooltip: 'adversary deception and engagement activities' },
  { path: '/frameworks/react', label: 'RE&CT', tooltip: 'incident response actions and playbooks' },
  { path: '/cti/sigma', label: 'Sigma Rules', tooltip: 'detection signatures mapped to techniques (SigmaHQ)' },
];

const extendedIntelNav: NavItem[] = [
  { path: '/external-actors', label: 'Non-MITRE Actors', tooltip: '500+ threat actors from ThaiCERT encyclopedia' },
];

function NavItemLink({ path, label, tooltip, end }: NavItem & { end?: boolean }) {
  return (
    <NavLink
      to={path}
      end={end}
      title={tooltip}
      className={({ isActive }) =>
        [
          'block px-3 py-2 rounded-md text-sm font-medium transition-colors duration-150',
          isActive
            ? 'text-[var(--accent-teal)] bg-[var(--teal-faint)] border-l-2 border-[var(--accent-teal)]'
            : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]',
        ].join(' ')
      }
    >
      {label}
    </NavLink>
  );
}

function CollapsibleNavSection({ label, items, defaultOpen = false, title }: { label: string; items: NavItem[]; defaultOpen?: boolean; title?: string }) {
  const location = useLocation();
  const isActiveRoute = items.some((item) => location.pathname.startsWith(item.path));
  const [open, setOpen] = useState(defaultOpen || isActiveRoute);

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
            <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} />
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
        'fixed top-0 left-0 h-screen w-60 bg-[var(--surface-card)] border-r border-[var(--border-color)] flex flex-col z-50 overflow-y-auto',
        'transition-transform duration-200 ease-in-out',
        open ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
      ].join(' ')}
      aria-label="Main navigation"
    >
      {/* Logo / Title */}
      <div className="px-4 py-5 border-b border-[var(--border-color)] flex items-center justify-between">
        <Link to="/" className="group">
          <div className="text-[var(--accent-teal)] font-bold text-sm tracking-widest uppercase group-hover:text-[var(--accent-teal-light)] transition-colors">
            MITRE ATT&amp;CK
          </div>
          <div className="text-[var(--text-secondary)] text-xs mt-0.5 group-hover:text-[var(--text-primary)] transition-colors">Explorer Plus</div>
        </Link>
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

      {/* Domain & Sector filters — below logo */}
      <div className="px-3 py-3 border-b border-[var(--border-color)] space-y-2">
        <DomainDropdown />
        <SectorDropdown />
      </div>

      {/* Main Nav */}
      <nav
        className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto
          [scrollbar-width:thin] [scrollbar-color:var(--border-color)_transparent]
          [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-track]:bg-transparent
          [&::-webkit-scrollbar-thumb]:bg-[var(--border-color)] [&::-webkit-scrollbar-thumb]:rounded-full"
      >
        {mainSections.map((section, si) => (
          <div key={si} className={si > 0 ? 'mt-3 pt-3 border-t border-[var(--border-faint)]' : ''}>
            {section.label ? (
              <CollapsibleNavSection label={section.label} items={section.items} />
            ) : (
              section.items.map((item) => (
                <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} end={item.path === '/'} />
              ))
            )}
          </div>
        ))}
      </nav>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* CTI Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 ml-1 border-l-2 border-[var(--teal-muted)] pl-2 text-[11px] font-bold text-[var(--accent-teal)] uppercase tracking-widest">
          CTI
        </div>
        <div className="space-y-0.5">
          {ctiNav.map((item) => (
            <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} />
          ))}
        </div>
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* Frameworks Section (collapsible) */}
      <div className="px-2 py-4">
        <CollapsibleNavSection label="Frameworks" items={frameworksNav} defaultOpen={false} title="Not filtered by sector" />
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[var(--border-color)]" />

      {/* Extended Intel Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 ml-1 border-l-2 border-[var(--teal-muted)] pl-2 text-[11px] font-bold text-[var(--accent-teal)] uppercase tracking-widest">
          Extended Intel
        </div>
        <div className="space-y-0.5">
          {extendedIntelNav.map((item) => (
            <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} />
          ))}
        </div>
      </div>
    </aside>
  );
}
