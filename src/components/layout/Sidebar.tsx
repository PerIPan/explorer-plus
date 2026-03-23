import { NavLink, Link } from 'react-router-dom';

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
      { path: '/', label: 'Relationships', tooltip: 'explore entity connections — graph, actor profiles, technique maps' },
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
  { path: '/cti/iocs', label: 'IOCs', tooltip: 'CVEs, hashes, domains, IPs from AlienVault OTX, CISA KEV' },
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
            ? 'text-[#64ffda] bg-[#64ffda1a] border-l-2 border-[#64ffda]'
            : 'text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08]',
        ].join(' ')
      }
    >
      {label}
    </NavLink>
  );
}

export function Sidebar({ open, onClose }: SidebarProps) {
  return (
    <aside
      className={[
        'fixed top-0 left-0 h-screen w-60 bg-[#16213e] border-r border-[#2a2a4a] flex flex-col z-50 overflow-y-auto',
        'transition-transform duration-200 ease-in-out',
        open ? 'translate-x-0' : '-translate-x-full lg:translate-x-0',
      ].join(' ')}
      aria-label="Main navigation"
    >
      {/* Logo / Title */}
      <div className="px-4 py-5 border-b border-[#2a2a4a] flex items-center justify-between">
        <Link to="/" className="group">
          <div className="text-[#64ffda] font-bold text-sm tracking-widest uppercase group-hover:text-[#9efce5] transition-colors">
            MITRE ATT&amp;CK
          </div>
          <div className="text-[#8892b0] text-xs mt-0.5 group-hover:text-[#ccd6f6] transition-colors">Explorer Plus</div>
        </Link>
        {/* Close button — visible only below lg */}
        <button
          type="button"
          aria-label="Close navigation menu"
          onClick={onClose}
          className="lg:hidden p-1 rounded-md text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08] transition-colors"
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

      {/* Main Nav */}
      <nav
        className="flex-1 px-2 py-4 space-y-0.5 overflow-y-auto
          [scrollbar-width:thin] [scrollbar-color:#2a2a4a_transparent]
          [&::-webkit-scrollbar]:w-1 [&::-webkit-scrollbar-track]:bg-transparent
          [&::-webkit-scrollbar-thumb]:bg-[#2a2a4a] [&::-webkit-scrollbar-thumb]:rounded-full"
      >
        {mainSections.map((section, si) => (
          <div key={si} className={si > 0 ? 'mt-3 pt-3 border-t border-[#2a2a4a33]' : ''}>
            {section.label && (
              <div className="px-3 mb-1.5 ml-1 border-l-2 border-[#64ffda44] pl-2 text-[11px] font-bold text-[#64ffda] uppercase tracking-widest">
                {section.label}
              </div>
            )}
            {section.items.map((item) => (
              <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} end={item.path === '/'} />
            ))}
          </div>
        ))}
      </nav>

      {/* Separator */}
      <div className="mx-4 border-t border-[#2a2a4a]" />

      {/* CTI Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 ml-1 border-l-2 border-[#64ffda44] pl-2 text-[11px] font-bold text-[#64ffda] uppercase tracking-widest" title="Not filtered by sector">
          CTI
        </div>
        <div className="space-y-0.5">
          {ctiNav.map((item) => (
            <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} />
          ))}
        </div>
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[#2a2a4a]" />

      {/* Frameworks Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 ml-1 border-l-2 border-[#64ffda44] pl-2 text-[11px] font-bold text-[#64ffda] uppercase tracking-widest" title="Not filtered by sector">
          Frameworks
        </div>
        <div className="space-y-0.5">
          {frameworksNav.map((item) => (
            <NavItemLink key={item.path} path={item.path} label={item.label} tooltip={item.tooltip} />
          ))}
        </div>
      </div>

      {/* Separator */}
      <div className="mx-4 border-t border-[#2a2a4a]" />

      {/* Extended Intel Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 ml-1 border-l-2 border-[#64ffda44] pl-2 text-[11px] font-bold text-[#64ffda] uppercase tracking-widest">
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
