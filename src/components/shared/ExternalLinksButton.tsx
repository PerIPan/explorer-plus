import { useState } from 'react';

interface ExternalLink {
  label: string;
  url: string;
  description?: string;
}

type EntityType = 'technique' | 'group' | 'software' | 'campaign' | 'mitigation' | 'tactic' | 'data_source';

function buildLinks(type: EntityType, attackId: string, name: string): ExternalLink[] {
  const links: ExternalLink[] = [];

  const MITRE_BASE = 'https://attack.mitre.org';

  switch (type) {
    case 'technique':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/techniques/${attackId.replace('.', '/')}`, description: 'Official technique page' },
        { label: 'CTID Mappings', url: `https://center-for-threat-informed-defense.github.io/mappings-explorer/`, description: 'Framework mappings explorer' },
      );
      break;
    case 'group':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/groups/${attackId}`, description: 'Official group page' },
      );
      break;
    case 'software':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/software/${attackId}`, description: 'Official software page' },
      );
      break;
    case 'campaign':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/campaigns/${attackId}`, description: 'Official campaign page' },
      );
      break;
    case 'mitigation':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/mitigations/${attackId}`, description: 'Official mitigation page' },
      );
      break;
    case 'tactic':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/tactics/${attackId}`, description: 'Official tactic page' },
      );
      break;
    case 'data_source':
      links.push(
        { label: 'MITRE ATT&CK', url: `${MITRE_BASE}/datasources/${attackId}`, description: 'Official data source page' },
      );
      break;
  }

  // Google search as fallback for more context
  links.push(
    { label: 'Search', url: `https://www.google.com/search?q=${encodeURIComponent(`MITRE ATT&CK ${attackId} ${name}`)}`, description: 'Search for more context' },
  );

  return links;
}

interface ExternalLinksButtonProps {
  type: EntityType;
  attackId: string;
  name: string;
}

export function ExternalLinksButton({ type, attackId, name }: ExternalLinksButtonProps) {
  const [open, setOpen] = useState(false);
  const links = buildLinks(type, attackId, name);

  return (
    <>
      <div className="relative ml-1">
        <button
          type="button"
          onClick={() => setOpen(!open)}
          className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
          title="External references"
        >
          <svg className="w-2.5 h-2.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
          </svg>
          ext
        </button>

        {open && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
            <div className="absolute top-full left-0 mt-1 z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-xl w-64">
              <div className="px-3 py-2 border-b border-[var(--border-color)]">
                <span className="text-[10px] text-[var(--text-secondary)] font-mono">{attackId}</span>
              </div>
              <div className="p-1.5 space-y-0.5">
                {links.map((link) => (
                  <a
                    key={link.url}
                    href={link.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 px-2 py-1.5 rounded hover:bg-[var(--teal-ghost)] transition-colors group"
                  >
                    <svg className="w-3 h-3 text-[var(--accent-teal)] shrink-0 opacity-50 group-hover:opacity-100" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                    </svg>
                    <div className="min-w-0">
                      <div className="text-xs text-[var(--text-primary)] group-hover:text-[var(--accent-teal)]">{link.label}</div>
                      {link.description && (
                        <div className="text-[9px] text-[var(--text-secondary)] truncate">{link.description}</div>
                      )}
                    </div>
                  </a>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </>
  );
}
