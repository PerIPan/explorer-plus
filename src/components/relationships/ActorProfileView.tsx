import { useState } from 'react';
import { useGroup, useCampaign, useExternalActorByGroup } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import type { GroupTechnique, GroupSoftware, GroupCampaign, GroupSector, ExternalActor } from '../../lib/types';

// ── Tactic ordering ────────────────────────────────────────────────────────────

const TACTIC_ORDER = [
  'Reconnaissance',
  'Resource Development',
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
];

/** Group techniques by their tactic prefix (heuristic: procedure context not available; use technique name patterns).
 *  The group detail API does NOT return tactic info per technique — we derive tactic from the procedure/name
 *  when the API enriches it. For now we show techniques grouped by platform as a fallback.
 *  To stay honest with real data, we parse the attackId parent prefix for sub-techniques.
 */
function groupByTactic(techniques: GroupTechnique[]): Map<string, GroupTechnique[]> {
  // The group detail endpoint does not include tactic names per technique.
  // We bucket by "no tactic info" and expose the flat list to avoid inventing data.
  const map = new Map<string, GroupTechnique[]>();
  for (const t of techniques) {
    // Sub-techniques share a parent prefix (e.g. T1059.001 → T1059)
    const bucket = 'All Techniques';
    const existing = map.get(bucket) ?? [];
    existing.push(t);
    map.set(bucket, existing);
  }
  return map;
}

// ── Collapsible section ────────────────────────────────────────────────────────

interface CollapsibleSectionProps {
  title: string;
  count?: number;
  badge?: { label: string; variant: 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral' };
  defaultOpen?: boolean;
  children: React.ReactNode;
}

function CollapsibleSection({ title, count, badge, defaultOpen = false, children }: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border border-[#2a2a4a] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[#16213e] hover:bg-[#1a2a4a] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-semibold text-[#ccd6f6] truncate">{title}</span>
          {count !== undefined && (
            <span className="text-xs text-[#8892b0] shrink-0">({count})</span>
          )}
          {badge && <Badge label={badge.label} variant={badge.variant} />}
        </div>
        <svg
          className={`w-4 h-4 text-[#8892b0] shrink-0 transition-transform duration-200 ${open ? 'rotate-180' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && (
        <div className="px-4 py-3 bg-[#0f1929] space-y-1.5">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Sub-section for nested collapsibles ───────────────────────────────────────

interface NestedSectionProps {
  title: string;
  count?: number;
  children: React.ReactNode;
}

function NestedSection({ title, count, children }: NestedSectionProps) {
  const [open, setOpen] = useState(false);

  return (
    <div className="ml-3 border-l border-[#2a2a4a] pl-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 py-1 text-xs text-[#8892b0] hover:text-[#ccd6f6] transition-colors"
      >
        <svg
          className={`w-3 h-3 shrink-0 transition-transform duration-150 ${open ? 'rotate-90' : ''}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
        </svg>
        <span className="font-medium">{title}</span>
        {count !== undefined && <span className="opacity-60">({count})</span>}
      </button>
      {open && (
        <div className="flex flex-wrap gap-1.5 pt-1.5 pb-2">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Campaign card inside the actor profile ─────────────────────────────────────

function CampaignCard({ campaign }: { campaign: GroupCampaign }) {
  const { data, isLoading } = useCampaign(campaign.attackId);

  return (
    <CollapsibleSection
      title={campaign.name}
      badge={{ label: campaign.attackId, variant: 'blue' }}
    >
      {isLoading && (
        <div className="flex items-center gap-2 text-[#8892b0] text-xs py-2">
          <span className="inline-block w-3 h-3 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin" />
          Loading campaign details...
        </div>
      )}
      {!isLoading && data && (
        <>
          {data.techniques && data.techniques.length > 0 && (
            <NestedSection title="Techniques" count={data.techniques.length}>
              {data.techniques.map((t) => (
                <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
              ))}
            </NestedSection>
          )}
          {data.software && data.software.length > 0 && (
            <NestedSection title="Software" count={data.software.length}>
              {data.software.map((s) => (
                <EntityLink key={s.attackId} type="software" attackId={s.attackId} name={s.name} />
              ))}
            </NestedSection>
          )}
          {!data.techniques?.length && !data.software?.length && (
            <p className="text-xs text-[#8892b0] py-1">No techniques or software recorded for this campaign.</p>
          )}
        </>
      )}
      {!isLoading && !data && (
        <p className="text-xs text-[#f97316] py-1">Campaign details unavailable.</p>
      )}
    </CollapsibleSection>
  );
}

// ── Software Arsenal ───────────────────────────────────────────────────────────

function SoftwareArsenal({ software }: { software: GroupSoftware[] }) {
  const malware = software.filter((s) => s.type === 'malware');
  const tools = software.filter((s) => s.type === 'tool');

  return (
    <div className="space-y-1.5">
      {malware.length > 0 && (
        <NestedSection title="Malware" count={malware.length}>
          {malware.map((s) => (
            <div key={s.attackId} className="flex items-center gap-1">
              <EntityLink type="software" attackId={s.attackId} name={s.name} />
              <Badge label="malware" variant="pink" />
            </div>
          ))}
        </NestedSection>
      )}
      {tools.length > 0 && (
        <NestedSection title="Tools" count={tools.length}>
          {tools.map((s) => (
            <div key={s.attackId} className="flex items-center gap-1">
              <EntityLink type="software" attackId={s.attackId} name={s.name} />
              <Badge label="tool" variant="purple" />
            </div>
          ))}
        </NestedSection>
      )}
    </div>
  );
}

// ── Techniques by tactic ───────────────────────────────────────────────────────

function TechniquesByTactic({ techniques }: { techniques: GroupTechnique[] }) {
  // Sort: sub-techniques after parents, then alphabetical
  const sorted = [...techniques].sort((a, b) => a.attackId.localeCompare(b.attackId));

  // Group by parent technique ID for sub-technique nesting
  const parents = sorted.filter((t) => !t.attackId.includes('.'));
  const subs = sorted.filter((t) => t.attackId.includes('.'));
  const subsByParent = new Map<string, GroupTechnique[]>();
  for (const sub of subs) {
    const parentId = sub.attackId.split('.')[0];
    const existing = subsByParent.get(parentId) ?? [];
    existing.push(sub);
    subsByParent.set(parentId, existing);
  }

  // Collect standalone subs whose parent isn't in group technique list
  const parentIds = new Set(parents.map((t) => t.attackId));
  const orphanSubs = subs.filter((s) => !parentIds.has(s.attackId.split('.')[0]));

  const displayList = [...parents, ...orphanSubs];

  return (
    <div className="space-y-1">
      {displayList.map((t) => {
        const children = subsByParent.get(t.attackId) ?? [];
        return (
          <div key={t.attackId}>
            <div className="flex items-center gap-2 py-0.5">
              <EntityLink type="technique" attackId={t.attackId} name={t.name} />
            </div>
            {children.length > 0 && (
              <div className="ml-4 pl-2 border-l border-[#2a2a4a] space-y-0.5 mt-0.5">
                {children.map((sub) => (
                  <div key={sub.attackId} className="flex items-center gap-2 py-0.5">
                    <EntityLink type="technique" attackId={sub.attackId} name={sub.name} />
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

// ── Targeted Sectors ───────────────────────────────────────────────────────────

function TargetedSectors({ sectors }: { sectors: GroupSector[] }) {
  const SECTOR_COLORS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink' | 'yellow' | 'neutral'> = {
    Government: 'blue',
    Defense: 'orange',
    Technology: 'teal',
    Finance: 'green',
    Healthcare: 'pink',
    Energy: 'yellow',
    Telecommunications: 'purple',
  };

  return (
    <div className="flex flex-wrap gap-1.5">
      {sectors.map((s) => (
        <Badge
          key={s.name}
          label={s.name}
          variant={SECTOR_COLORS[s.name] ?? 'neutral'}
        />
      ))}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface ActorProfileViewProps {
  /** attackId for a group (Gxxxx) or campaign (Cxxxx) */
  attackId: string;
  entityType: 'group' | 'campaign';
}

/**
 * Hierarchical actor profile showing campaigns, techniques, software, and sectors
 * for a threat group or campaign entity.
 */
export function ActorProfileView({ attackId, entityType }: ActorProfileViewProps) {
  const groupResult = useGroup(entityType === 'group' ? attackId : '');
  const campaignResult = useCampaign(entityType === 'campaign' ? attackId : '');
  const thaiCertResult = useExternalActorByGroup(entityType === 'group' ? attackId : '');

  const isLoading = entityType === 'group' ? groupResult.isLoading : campaignResult.isLoading;
  const error = entityType === 'group' ? groupResult.error : campaignResult.error;

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[#8892b0] text-sm py-8 justify-center">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin" />
        Loading actor profile...
      </div>
    );
  }

  if (error) {
    return (
      <div className="text-[#f97316] text-sm py-8 text-center">
        Failed to load actor profile.
      </div>
    );
  }

  // ── Group profile ──────────────────────────────────────────────────────────

  if (entityType === 'group') {
    const group = groupResult.data;
    if (!group) return null;

    const techniques: GroupTechnique[] = (group.techniques as GroupTechnique[] | undefined) ?? [];
    const software: GroupSoftware[] = (group.software as GroupSoftware[] | undefined) ?? [];
    const campaigns: GroupCampaign[] = (group.campaigns as GroupCampaign[] | undefined) ?? [];
    const sectors: GroupSector[] = (group.sectors as GroupSector[] | undefined) ?? [];

    return (
      <div className="space-y-3">
        {/* Header */}
        <div className="flex items-start gap-3 pb-1">
          <div>
            <h2 className="text-lg font-semibold text-[#ccd6f6]">{group.name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="font-mono text-xs text-[#f97316] bg-[#f9731618] border border-[#f9731633] px-2 py-0.5 rounded">
                {group.attackId}
              </span>
              <Badge label="group" variant="orange" />
              {group.aliases && group.aliases.length > 0 && (
                <span className="text-xs text-[#8892b0]">
                  aka {group.aliases.join(', ')}
                  {group.aliases.length > 3 && ` +${group.aliases.length - 3} more`}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Targeted Sectors — first */}
        {sectors.length > 0 && (
          <CollapsibleSection title="Targeted Sectors" count={sectors.length} defaultOpen>
            <TargetedSectors sectors={sectors} />
          </CollapsibleSection>
        )}

        {/* Campaigns */}
        {campaigns.length > 0 && (
          <CollapsibleSection title="Campaigns" count={campaigns.length} defaultOpen>
            <div className="space-y-2">
              {campaigns.map((c) => (
                <CampaignCard key={c.attackId} campaign={c} />
              ))}
            </div>
          </CollapsibleSection>
        )}

        {/* Techniques */}
        {techniques.length > 0 && (
          <CollapsibleSection title="Techniques" count={techniques.length} defaultOpen>
            <TechniquesByTactic techniques={techniques} />
          </CollapsibleSection>
        )}

        {/* Software */}
        {software.length > 0 && (
          <CollapsibleSection title="Software Arsenal" count={software.length} defaultOpen>
            <SoftwareArsenal software={software} />
          </CollapsibleSection>
        )}

        {/* ThaiCERT Extended Intelligence */}
        {thaiCertResult.data?.data && thaiCertResult.data.data.length > 0 && (
          <CollapsibleSection
            title="ThaiCERT Intelligence"
            count={thaiCertResult.data.data.length}
            defaultOpen
          >
            <div className="space-y-3">
              {thaiCertResult.data.data.map((actor: ExternalActor) => (
                <div key={actor.id} className="bg-[#0a0a1a] border border-[#2a2a4a] rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-[#94a3b8]">{actor.name}</span>
                    <Badge label="ThaiCERT / ETDA" variant="neutral" />
                    {actor.country && <Badge label={actor.country} variant="blue" />}
                    {actor.attributionConfidence && (
                      <span className="text-[10px] text-[#8892b0]">confidence: {actor.attributionConfidence}</span>
                    )}
                  </div>
                  {actor.motivation && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#8892b0]">Motivation:</span>
                      <span className="text-xs text-[#ccd6f6]">{actor.motivation}</span>
                    </div>
                  )}
                  {actor.suspectedStateSponsor && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[#8892b0]">State sponsor:</span>
                      <Badge label={actor.suspectedStateSponsor} variant="orange" />
                    </div>
                  )}
                  {actor.suspectedVictims && actor.suspectedVictims.length > 0 && (
                    <div>
                      <span className="text-xs text-[#8892b0]">Suspected victims:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {actor.suspectedVictims.map((v) => (
                          <Badge key={v} label={v} variant="purple" />
                        ))}
                      </div>
                    </div>
                  )}
                  {actor.targetCategories && actor.targetCategories.length > 0 && (
                    <div>
                      <span className="text-xs text-[#8892b0]">Target categories:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {actor.targetCategories.map((c) => (
                          <Badge key={c} label={c} variant="green" />
                        ))}
                      </div>
                    </div>
                  )}
                  {actor.refs && actor.refs.length > 0 && (
                    <div>
                      <span className="text-xs text-[#8892b0]">{actor.refs.length} references</span>
                    </div>
                  )}
                </div>
              ))}
              <p className="text-[10px] text-[#4a4a6a] pt-1">
                Source: ThaiCERT / ETDA Threat Actor Encyclopedia — not affiliated with MITRE
              </p>
            </div>
          </CollapsibleSection>
        )}

        {techniques.length === 0 && software.length === 0 && campaigns.length === 0 && (
          <p className="text-[#8892b0] text-sm py-4 text-center">
            No relationship data available for this group.
          </p>
        )}
      </div>
    );
  }

  // ── Campaign profile ───────────────────────────────────────────────────────

  const campaign = campaignResult.data;
  if (!campaign) return null;

  const techniques = campaign.techniques ?? [];
  const software = campaign.software ?? [];
  const groups = campaign.groups ?? [];

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-start gap-3 pb-1">
        <div>
          <h2 className="text-lg font-semibold text-[#ccd6f6]">{campaign.name}</h2>
          <div className="flex items-center gap-2 mt-1">
            <span className="font-mono text-xs text-[#60a5fa] bg-[#60a5fa18] border border-[#60a5fa33] px-2 py-0.5 rounded">
              {campaign.attackId}
            </span>
            <Badge label="campaign" variant="blue" />
            {campaign.firstSeen && (
              <span className="text-xs text-[#8892b0]">
                {new Date(campaign.firstSeen).getFullYear()}
                {campaign.lastSeen ? ` – ${new Date(campaign.lastSeen).getFullYear()}` : ''}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Attributed Groups */}
      {groups.length > 0 && (
        <CollapsibleSection title="Attributed Groups" count={groups.length} defaultOpen>
          <div className="flex flex-wrap gap-1.5">
            {groups.map((g) => (
              <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Techniques */}
      {techniques.length > 0 && (
        <CollapsibleSection title="Techniques Used" count={techniques.length} defaultOpen>
          <div className="flex flex-wrap gap-1.5">
            {techniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Software */}
      {software.length > 0 && (
        <CollapsibleSection title="Software" count={software.length} defaultOpen>
          <div className="flex flex-wrap gap-1.5">
            {software.map((s) => (
              <div key={s.attackId} className="flex items-center gap-1">
                <EntityLink type="software" attackId={s.attackId} name={s.name} />
                <Badge label={s.type} variant={s.type === 'malware' ? 'pink' : 'purple'} />
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {techniques.length === 0 && software.length === 0 && groups.length === 0 && (
        <p className="text-[#8892b0] text-sm py-4 text-center">
          No relationship data available for this campaign.
        </p>
      )}
    </div>
  );
}
