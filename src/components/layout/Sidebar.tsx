import { NavLink } from 'react-router-dom';

interface SidebarProps {
  open: boolean;
  onClose: () => void;
}

interface NavItem {
  path: string;
  label: string;
}

const mainNav: NavItem[] = [
  { path: '/', label: 'Dashboard' },
  { path: '/matrix', label: 'Matrix' },
  { path: '/techniques', label: 'Techniques' },
  { path: '/groups', label: 'Groups' },
  { path: '/campaigns', label: 'Campaigns' },
  { path: '/software', label: 'Software' },
  { path: '/data-sources', label: 'Data Sources' },
  { path: '/mitigations', label: 'Mitigations' },
  { path: '/tactics', label: 'Tactics' },
  { path: '/sectors', label: 'Sectors' },
  { path: '/relationships', label: 'Relationships' },
];

const ctiNav: NavItem[] = [
  { path: '/cti/reports', label: 'Reports' },
  { path: '/cti/iocs', label: 'IOCs' },
  { path: '/cti/sigma', label: 'Sigma' },
  { path: '/cti/feed-status', label: 'Feed Status' },
];

function NavItem({ path, label, end }: NavItem & { end?: boolean }) {
  return (
    <NavLink
      to={path}
      end={end}
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
        <div>
          <div className="text-[#64ffda] font-bold text-sm tracking-widest uppercase">
            MITRE ATT&amp;CK
          </div>
          <div className="text-[#8892b0] text-xs mt-0.5">Explorer</div>
        </div>
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
        <div className="px-3 mb-2 text-[10px] font-semibold text-[#8892b0] uppercase tracking-widest">
          ATT&amp;CK
        </div>
        {mainNav.map((item) => (
          <NavItem key={item.path} path={item.path} label={item.label} end={item.path === '/'} />
        ))}
      </nav>

      {/* Separator */}
      <div className="mx-4 border-t border-[#2a2a4a]" />

      {/* CTI Section */}
      <div className="px-2 py-4">
        <div className="px-3 mb-2 text-[10px] font-semibold text-[#8892b0] uppercase tracking-widest">
          CTI
        </div>
        <div className="space-y-0.5">
          {ctiNav.map((item) => (
            <NavItem key={item.path} path={item.path} label={item.label} />
          ))}
        </div>
      </div>
    </aside>
  );
}
