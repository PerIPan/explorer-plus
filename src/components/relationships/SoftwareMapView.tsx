import { useState } from 'react';
import { useSoftwareDetail } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';
import { ExternalLinksButton } from '../shared/ExternalLinksButton';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { getParentId } from '../../lib/getParentId';

// ── Local types for detail-endpoint extras ─────────────────────────────────────

interface SoftwareTechnique {
  attackId: string;
  name: string;
  procedure: string | null;
  platforms: string[] | null;
}

interface SoftwareGroup {
  attackId: string;
  name: string;
  description: string | null;
}

interface SoftwareCampaign {
  attackId: string;
  name: string;
  description: string | null;
}

/** The /software/:id detail response extends the base Software type. */
interface SoftwareDetail {
  attackId: string;
  name: string;
  description: string | null;
  type: 'malware' | 'tool';
  platforms: string[] | null;
  aliases: string[] | null;
  domain: string | null;
  techniques: SoftwareTechnique[];
  groups: SoftwareGroup[];
  campaigns: SoftwareCampaign[];
}

// ── Collapsible card ──────────────────────────────────────────────────────────

interface MapCardProps {
  label: string;
  icon: React.ReactNode;
  count?: number;
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function MapCard({ label, icon, count, defaultOpen = true, children }: MapCardProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border border-[var(--border-color)] rounded-lg overflow-visible">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2">
          <span className="text-[var(--accent-teal)] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">
            {label}
          </span>
          {count !== undefined && (
            <span className="text-xs text-[var(--text-secondary)]">({count})</span>
          )}
        </div>
        <svg
          className={`w-4 h-4 text-[var(--text-secondary)] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">{children}</div>
      )}
    </div>
  );
}

/** Labeled row inside a MapCard */
function MapRow({ prefix, children }: { prefix: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{prefix}</span>
      <div className="flex-1 flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

const IconPeople = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      d="M17 20h5v-2a4 4 0 00-5-3.87M9 20H4v-2a4 4 0 015-3.87m6 5.87v-2a6 6 0 00-12 0v2m6-6a4 4 0 110-8 4 4 0 010 8z"
    />
  </svg>
);

const IconCrosshair = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <circle cx="12" cy="12" r="9" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="12" cy="12" r="3" strokeLinecap="round" strokeLinejoin="round" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v3M12 18v3M3 12h3M18 12h3" />
  </svg>
);

const IconServer = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <rect x="2" y="3" width="20" height="5" rx="1" strokeLinecap="round" strokeLinejoin="round" />
    <rect x="2" y="10" width="20" height="5" rx="1" strokeLinecap="round" strokeLinejoin="round" />
    <rect x="2" y="17" width="20" height="4" rx="1" strokeLinecap="round" strokeLinejoin="round" />
    <circle cx="6" cy="5.5" r="0.5" fill="currentColor" />
    <circle cx="6" cy="12.5" r="0.5" fill="currentColor" />
  </svg>
);

// ── Technique list with parent/sub-technique nesting ──────────────────────────

function TechniqueTree({ techniques }: { techniques: SoftwareTechnique[] }) {
  const sorted = [...techniques].sort((a, b) => a.attackId.localeCompare(b.attackId));

  const parents = sorted.filter((t) => !t.attackId.includes('.'));
  const subs = sorted.filter((t) => t.attackId.includes('.'));

  const subsByParent = new Map<string, SoftwareTechnique[]>();
  for (const sub of subs) {
    const parentId = getParentId(sub.attackId);
    const existing = subsByParent.get(parentId) ?? [];
    existing.push(sub);
    subsByParent.set(parentId, existing);
  }

  const parentIds = new Set(parents.map((t) => t.attackId));
  const orphanSubs = subs.filter((s) => !parentIds.has(getParentId(s.attackId)));

  const displayList = [...parents, ...orphanSubs];

  return (
    <div className="space-y-1">
      {displayList.map((t) => {
        const children = subsByParent.get(t.attackId) ?? [];
        return (
          <div key={t.attackId}>
            <div className="flex items-center gap-2 py-0.5">
              <EntityLink type="technique" attackId={t.attackId} name={t.name} useMap />
            </div>
            {children.length > 0 && (
              <div className="ml-4 pl-2 border-l border-[var(--border-color)] space-y-0.5 mt-0.5">
                {children.map((sub) => (
                  <div key={sub.attackId} className="flex items-center gap-2 py-0.5">
                    <EntityLink type="technique" attackId={sub.attackId} name={sub.name} useMap />
                  </div>
                ))}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface SoftwareMapViewProps {
  attackId: string;
}

/**
 * Structured overview of a software entity (malware or tool):
 * type, platforms, aliases, who uses it (groups), and techniques employed.
 */
export function SoftwareMapView({ attackId }: SoftwareMapViewProps) {
  const { data, isLoading, error } = useSoftwareDetail(attackId);

  if (isLoading) {
    return <DiamondLoader text="Loading software map..." />;
  }

  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load software data.
      </div>
    );
  }

  // Cast to detail shape — the /software/:id endpoint includes techniques + groups
  const software = data as unknown as SoftwareDetail;

  const techniques: SoftwareTechnique[] = software.techniques ?? [];
  const groups: SoftwareGroup[] = software.groups ?? [];
  const campaigns: SoftwareCampaign[] = software.campaigns ?? [];
  const platforms: string[] = software.platforms ?? [];
  const aliases: string[] = software.aliases ?? [];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="pb-1">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{software.name}</h2>
          <ExternalLinksButton type="software" attackId={software.attackId} name={software.name} />
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-purple)] bg-[var(--purple-faint)] border border-[var(--purple-dim)] px-2 py-0.5 rounded">
            {software.attackId}
          </span>
          <Badge
            label={software.type}
            variant={software.type === 'malware' ? 'pink' : 'purple'}
          />
          {software.domain && (
            <Badge label={software.domain.replace('-attack', '')} variant="neutral" />
          )}
          {platforms.map((p) => (
            <Badge key={p} label={p} variant="blue" />
          ))}
        </div>
      </div>

      {/* Description */}
      {software.description && (
        <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4">
          <p
            className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap break-words"
            dangerouslySetInnerHTML={{
              __html: sanitize(sanitizeMarkdown(software.description)),
            }}
          />
        </div>
      )}

      {/* WHO USES IT */}
      <MapCard label="Who Uses It" icon={IconPeople} count={groups.length + campaigns.length}>
        {groups.length > 0 ? (
          <MapRow prefix="Groups">
            <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
              {groups.map((g) => (
                <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} useMap />
              ))}
            </div>
          </MapRow>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">
            No groups documented for this software.
          </p>
        )}
        {campaigns.length > 0 && (
          <MapRow prefix="Campaigns">
            <div className="flex flex-wrap gap-1.5">
              {campaigns.map((c) => (
                <EntityLink key={c.attackId} type="campaign" attackId={c.attackId} name={c.name} useMap />
              ))}
            </div>
          </MapRow>
        )}
      </MapCard>

      {/* TECHNIQUES */}
      <MapCard label="Techniques" icon={IconCrosshair} count={techniques.length}>
        {techniques.length > 0 ? (
          <TechniqueTree techniques={techniques} />
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No techniques linked.</p>
        )}
      </MapCard>

      {/* PLATFORMS + ALIASES */}
      {(platforms.length > 0 || aliases.length > 0) && (
        <MapCard label="Platforms" icon={IconServer} defaultOpen={platforms.length > 0}>
          {platforms.length > 0 && (
            <MapRow prefix="Platforms">
              {platforms.map((p) => (
                <Badge key={p} label={p} variant="blue" />
              ))}
            </MapRow>
          )}
          {aliases.length > 0 && (
            <MapRow prefix="Aliases">
              {aliases.map((a) => (
                <Badge key={a} label={a} variant="neutral" />
              ))}
            </MapRow>
          )}
        </MapCard>
      )}
    </div>
  );
}
