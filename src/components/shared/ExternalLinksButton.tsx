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
        { label: 'CTID Mappings', url: `https://center-for-threat-informed-defense.github.io/mappings-explorer/attack/${attackId}/`, description: 'Framework mappings for this technique' },
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
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium text-[var(--text-secondary)] bg-[var(--surface-alt)] border border-[var(--border-color)] hover:text-[var(--accent-teal)] hover:border-[var(--accent-teal)] transition-colors"
        title="External references"
      >
        <svg className="w-3 h-3" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
        </svg>
        External
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm"
          role="presentation"
          onClick={() => setOpen(false)}
        >
          <div
            className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-xl w-full max-w-sm mx-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--border-color)]">
              <div>
                <h3 className="text-sm font-semibold text-[var(--text-primary)]">External References</h3>
                <span className="text-[10px] text-[var(--text-secondary)] font-mono">{attackId}</span>
              </div>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="text-[var(--text-secondary)] hover:text-[var(--text-primary)] p-1"
                aria-label="Close"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="p-3 space-y-1">
              {links.map((link) => (
                <a
                  key={link.url}
                  href={link.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-3 px-3 py-2.5 rounded-md hover:bg-[var(--teal-ghost)] transition-colors group"
                >
                  <svg className="w-4 h-4 text-[var(--accent-teal)] shrink-0 opacity-60 group-hover:opacity-100" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                  </svg>
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-[var(--text-primary)] group-hover:text-[var(--accent-teal)]">{link.label}</div>
                    {link.description && (
                      <div className="text-[10px] text-[var(--text-secondary)] truncate">{link.description}</div>
                    )}
                  </div>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
