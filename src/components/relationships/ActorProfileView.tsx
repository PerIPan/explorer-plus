import { useState, useEffect } from 'react';
import { useGroup, useCampaign, useExternalActorByGroup, useExternalActorByName, useFrameworksByTechniques } from '../../hooks/useApi';
import { useDomain } from '../../contexts/DomainContext';
import { useSector } from '../../contexts/SectorContext';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';
import { RefsChevron } from '../shared/RefsChevron';
import { ctidCloudUrl, ctidVerisUrl } from '../../lib/urlSafety';
import { ExternalLinksButton } from '../shared/ExternalLinksButton';
import type { GroupTechnique, GroupSoftware, GroupCampaign, GroupSector, ExternalActor } from '../../lib/types';
import { DiamondLoader } from '../shared/FoldingDiamond';
import { getParentId } from '../../lib/getParentId';

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
    <div className="border border-[var(--border-color)] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-center justify-between px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-semibold text-[var(--text-primary)] truncate">{title}</span>
          {count !== undefined && (
            <span className="text-xs text-[var(--text-secondary)] shrink-0">({count})</span>
          )}
          {badge && <Badge label={badge.label} variant={badge.variant} />}
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
        <div className="px-4 py-3 bg-[var(--surface-alt)] space-y-1.5">
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
    <div className="ml-3 border-l border-[var(--border-color)] pl-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 py-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
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
        <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
          <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
          Loading campaign details...
        </div>
      )}
      {!isLoading && data && (
        <>
          {data.techniques && data.techniques.length > 0 && (
            <NestedSection title="Techniques" count={data.techniques.length}>
              {data.techniques.map((t) => (
                <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name}  useMap />
              ))}
            </NestedSection>
          )}
          {data.software && data.software.length > 0 && (
            <NestedSection title="Software" count={data.software.length}>
              {data.software.map((s) => (
                <EntityLink key={s.attackId} type="software" attackId={s.attackId} name={s.name}  useMap />
              ))}
            </NestedSection>
          )}
          {!data.techniques?.length && !data.software?.length && (
            <p className="text-xs text-[var(--text-secondary)] py-1">No techniques or software recorded for this campaign.</p>
          )}
        </>
      )}
      {!isLoading && !data && (
        <p className="text-xs text-[var(--accent-orange)] py-1">Campaign details unavailable.</p>
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
              <EntityLink type="software" attackId={s.attackId} name={s.name} useMap />
              <Badge label="malware" variant="pink" />
            </div>
          ))}
        </NestedSection>
      )}
      {tools.length > 0 && (
        <NestedSection title="Tools" count={tools.length}>
          {tools.map((s) => (
            <div key={s.attackId} className="flex items-center gap-1">
              <EntityLink type="software" attackId={s.attackId} name={s.name} useMap />
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
    const parentId = getParentId(sub.attackId);
    const existing = subsByParent.get(parentId) ?? [];
    existing.push(sub);
    subsByParent.set(parentId, existing);
  }

  // Collect standalone subs whose parent isn't in group technique list
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
              <EntityLink type="technique" attackId={t.attackId} name={t.name}  useMap />
            </div>
            {children.length > 0 && (
              <div className="ml-4 pl-2 border-l border-[var(--border-color)] space-y-0.5 mt-0.5">
                {children.map((sub) => (
                  <div key={sub.attackId} className="flex items-center gap-2 py-0.5">
                    <EntityLink type="technique" attackId={sub.attackId} name={sub.name}  useMap />
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
  /** attackId for a group (Gxxxx), campaign (Cxxxx), or external actor name */
  attackId: string;
  entityType: 'group' | 'campaign' | 'external_actor';
}

/**
 * Hierarchical actor profile showing campaigns, techniques, software, and sectors
 * for a threat group or campaign entity.
 */
export function ActorProfileView({ attackId, entityType }: ActorProfileViewProps) {
  const { domain, domainParam } = useDomain();
  const { sector } = useSector();
  const [showAllDomains, setShowAllDomains] = useState(false);
  // Reset toggle when actor changes
  useEffect(() => setShowAllDomains(false), [attackId]);
  const activeParams = showAllDomains ? {} : domainParam;
  const groupResult = useGroup(entityType === 'group' ? attackId : '', activeParams as Record<string, string>);
  const allDomainsResult = useGroup(entityType === 'group' ? attackId : '', {});
  const campaignResult = useCampaign(entityType === 'campaign' ? attackId : '');
  const thaiCertResult = useExternalActorByGroup(entityType === 'group' ? attackId : '');
  const externalActorResult = useExternalActorByName(entityType === 'external_actor' ? attackId : '');

  // Aggregate VERIS + Cloud frameworks from this entity's techniques
  const techniqueIds = (entityType === 'group' ? groupResult.data?.techniques : campaignResult.data?.techniques)
    ?.map((t: { attackId: string }) => t.attackId) ?? [];
  const fwResult = useFrameworksByTechniques(techniqueIds);

  // ── External actor profile (ThaiCERT / ETDA) ───────────────────────────
  if (entityType === 'external_actor') {
    if (externalActorResult.isLoading) {
      return (
        <DiamondLoader text="Loading actor profile..." />
      );
    }
    if (externalActorResult.error || !externalActorResult.data) {
      return (
        <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
          Failed to load actor profile.
        </div>
      );
    }
    const actor = externalActorResult.data;
    return (
      <div className="space-y-3">
        <div className="flex items-start gap-3 pb-1">
          <div>
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">{actor.name}</h2>
            <div className="flex items-center gap-2 mt-1">
              <Badge label="Non-MITRE" variant="neutral" />
              <Badge label="ThaiCERT / ETDA" variant="neutral" />
              {actor.country && <Badge label={actor.country} variant="blue" />}
              {actor.category && <Badge label={actor.category} variant="purple" />}
            </div>
          </div>
        </div>

        <CollapsibleSection title="ThaiCERT Intelligence" defaultOpen>
          <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4 space-y-2">
            {actor.description && (
              <p className="text-sm text-[var(--text-secondary)] leading-relaxed">{actor.description}</p>
            )}
            {actor.synonyms && actor.synonyms.length > 0 && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-[var(--text-secondary)]">Also known as:</span>
                {actor.synonyms.map((s) => (
                  <Badge key={s} label={s} variant="neutral" />
                ))}
              </div>
            )}
            {actor.firstSeen && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-secondary)]">First seen:</span>
                <span className="text-xs text-[var(--text-primary)]">{actor.firstSeen}</span>
              </div>
            )}
            {actor.motivation && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-secondary)]">Motivation:</span>
                <span className="text-xs text-[var(--text-primary)]">{actor.motivation}</span>
              </div>
            )}
            {actor.suspectedStateSponsor && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-secondary)]">State sponsor:</span>
                <Badge label={actor.suspectedStateSponsor} variant="orange" />
              </div>
            )}
            {actor.attributionConfidence && (
              <div className="flex items-center gap-2">
                <span className="text-xs text-[var(--text-secondary)]">Confidence:</span>
                <span className="text-xs text-[var(--text-primary)]">{actor.attributionConfidence}</span>
              </div>
            )}
            {actor.suspectedVictims && actor.suspectedVictims.length > 0 && (
              <div>
                <span className="text-xs text-[var(--text-secondary)]">Suspected victims:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {actor.suspectedVictims.map((v) => (
                    <Badge key={v} label={v} variant="purple" />
                  ))}
                </div>
              </div>
            )}
            {actor.targetCategories && actor.targetCategories.length > 0 && (
              <div>
                <span className="text-xs text-[var(--text-secondary)]">Target categories:</span>
                <div className="flex flex-wrap gap-1 mt-1">
                  {actor.targetCategories.map((c) => (
                    <Badge key={c} label={c} variant="green" />
                  ))}
                </div>
              </div>
            )}
            {actor.refs && actor.refs.length > 0 && (
              <RefsChevron refs={actor.refs} />
            )}
            {actor.mitreGroupId && (
              <div className="flex items-center gap-2 pt-1">
                <span className="text-xs text-[var(--text-secondary)]">MITRE mapping:</span>
                <span className="font-mono text-xs text-[var(--accent-orange)]">{actor.mitreGroupId}</span>
                {actor.mitreGroupName && (
                  <span className="text-xs text-[var(--text-primary)]">({actor.mitreGroupName})</span>
                )}
              </div>
            )}
          </div>
          <p className="text-[10px] text-[var(--text-secondary)] pt-1">
            Source: ThaiCERT / ETDA Threat Actor Encyclopedia — not affiliated with MITRE
          </p>
        </CollapsibleSection>
      </div>
    );
  }

  const isLoading = entityType === 'group' ? groupResult.isLoading : campaignResult.isLoading;
  const error = entityType === 'group' ? groupResult.error : campaignResult.error;

  if (isLoading) {
    return <DiamondLoader text="Loading actor profile..." />;
  }

  if (error) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
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

    // All-domain counts for the "show all" indicator
    const allTechniques: GroupTechnique[] = (allDomainsResult.data?.techniques as GroupTechnique[] | undefined) ?? [];
    const allSoftware: GroupSoftware[] = (allDomainsResult.data?.software as GroupSoftware[] | undefined) ?? [];
    const allCampaigns: GroupCampaign[] = (allDomainsResult.data?.campaigns as GroupCampaign[] | undefined) ?? [];
    const isDomainFiltered = domain !== 'all' && !showAllDomains;
    const hasMoreInOtherDomains = allTechniques.length > techniques.length || allSoftware.length > software.length || allCampaigns.length > campaigns.length;

    return (
      <div className="space-y-3">
        {/* Header */}
        <div className="flex items-start gap-3 pb-1">
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-semibold text-[var(--text-primary)]">{group.name}</h2>
              <ExternalLinksButton type="group" attackId={group.attackId} name={group.name} />
            </div>
            <div className="flex items-center gap-2 mt-1">
              <span className="font-mono text-xs text-[var(--accent-orange)] bg-[var(--orange-faint)] border border-[var(--orange-dim)] px-2 py-0.5 rounded">
                {group.attackId}
              </span>
              <Badge label="group" variant="orange" />
              {group.aliases && group.aliases.length > 0 && (
                <span className="text-xs text-[var(--text-secondary)]">
                  aka {group.aliases.join(', ')}
                  {group.aliases.length > 3 && ` +${group.aliases.length - 3} more`}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Domain filter indicator */}
        {isDomainFiltered && hasMoreInOtherDomains && (
          <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)] bg-[var(--surface-alt)] border border-[var(--border-color)] rounded-md px-3 py-2">
            <span>
              Showing <strong className="text-[var(--accent-teal)]">{domain.replace('-attack', '')}</strong> —{' '}
              {techniques.length} techniques, {software.length} software, {campaigns.length} campaigns
              {' '}({allTechniques.length} total across all domains)
            </span>
            <button
              type="button"
              onClick={() => setShowAllDomains(true)}
              className="text-[var(--accent-teal)] hover:underline font-medium shrink-0"
            >
              show all domains
            </button>
          </div>
        )}
        {showAllDomains && (
          <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)] bg-[var(--teal-ghost)] border border-[var(--teal-dim)] rounded-md px-3 py-2">
            <span>
              Showing <strong className="text-[var(--accent-teal)]">all domains</strong> —{' '}
              {techniques.length} techniques, {software.length} software, {campaigns.length} campaigns
            </span>
            <button
              type="button"
              onClick={() => setShowAllDomains(false)}
              className="text-[var(--accent-teal)] hover:underline font-medium shrink-0"
            >
              filter by {domain.replace('-attack', '')}
            </button>
          </div>
        )}

        {/* Sector mismatch warning */}
        {sector && sectors.length > 0 && !sectors.some((s) => s.slug === sector) && (
          <div className="text-xs text-[var(--accent-orange)] bg-[var(--orange-faint)] border border-[var(--orange-dim)] rounded-md px-3 py-2">
            This actor is not associated with the selected sector. Known sectors: {sectors.map((s) => s.name).join(', ')}
          </div>
        )}

        {/* Description */}
        {group.description && (
          <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4">
            <p
              className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap"
              dangerouslySetInnerHTML={{ __html: sanitize(sanitizeMarkdown(group.description)) }}
            />
          </div>
        )}

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

        {/* ThaiCERT Extended Intelligence — above techniques */}
        {thaiCertResult.data?.data && thaiCertResult.data.data.length > 0 && (
          <CollapsibleSection
            title="ThaiCERT Intelligence"
            count={thaiCertResult.data.data.length}
            defaultOpen
          >
            <div className="space-y-3">
              {thaiCertResult.data.data.map((actor: ExternalActor) => (
                <div key={actor.id} className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4 space-y-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-sm font-medium text-[var(--accent-neutral)]">{actor.name}</span>
                    <Badge label="ThaiCERT / ETDA" variant="neutral" />
                    {actor.country && <Badge label={actor.country} variant="blue" />}
                    {actor.attributionConfidence && (
                      <span className="text-[10px] text-[var(--text-secondary)]">confidence: {actor.attributionConfidence}</span>
                    )}
                  </div>
                  {actor.motivation && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[var(--text-secondary)]">Motivation:</span>
                      <span className="text-xs text-[var(--text-primary)]">{actor.motivation}</span>
                    </div>
                  )}
                  {actor.suspectedStateSponsor && (
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-[var(--text-secondary)]">State sponsor:</span>
                      <Badge label={actor.suspectedStateSponsor} variant="orange" />
                    </div>
                  )}
                  {actor.suspectedVictims && actor.suspectedVictims.length > 0 && (
                    <div>
                      <span className="text-xs text-[var(--text-secondary)]">Suspected victims:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {actor.suspectedVictims.map((v) => (
                          <Badge key={v} label={v} variant="purple" />
                        ))}
                      </div>
                    </div>
                  )}
                  {actor.targetCategories && actor.targetCategories.length > 0 && (
                    <div>
                      <span className="text-xs text-[var(--text-secondary)]">Target categories:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {actor.targetCategories.map((c) => (
                          <Badge key={c} label={c} variant="green" />
                        ))}
                      </div>
                    </div>
                  )}
                  {actor.refs && actor.refs.length > 0 && (
                    <RefsChevron refs={actor.refs} />
                  )}
                </div>
              ))}
              <p className="text-[10px] text-[var(--text-secondary)] pt-1">
                Source: ThaiCERT / ETDA Threat Actor Encyclopedia — not affiliated with MITRE
              </p>
            </div>
          </CollapsibleSection>
        )}

        {/* Software Arsenal */}
        {software.length > 0 && (
          <CollapsibleSection title="Software Arsenal" count={software.length} defaultOpen>
            <SoftwareArsenal software={software} />
          </CollapsibleSection>
        )}

        {/* Targeted Applications — collapsed */}
        {(group as { targetedApps?: Array<{ normalized: string; vendor: string; product: string; cveCount: number }> }).targetedApps?.length ? (
          <CollapsibleSection title="Targeted Applications" count={(group as { targetedApps: Array<unknown> }).targetedApps.length} defaultOpen={false}>
            <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto" tabIndex={0} aria-label="Targeted applications">
              {(group as { targetedApps: Array<{ normalized: string; vendor: string; product: string; cveCount: number }> }).targetedApps.map((app) => (
                <a
                  key={app.normalized}
                  href={`/?entity=${encodeURIComponent(app.normalized)}&tab=application-map`}
                  className="inline-flex items-center gap-1.5 px-2 py-1 rounded-md text-xs bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors"
                >
                  <span className="text-[var(--text-primary)]">{app.vendor} / {app.product}</span>
                  <Badge label={String(app.cveCount)} variant="pink" />
                </a>
              ))}
            </div>
          </CollapsibleSection>
        ) : null}

        {/* VERIS Categories — collapsed */}
        {fwResult.data?.veris && fwResult.data.veris.length > 0 && (
          <CollapsibleSection title="VERIS Incident Categories" count={fwResult.data.veris.length} defaultOpen={false}>
            <div className="flex flex-wrap gap-1.5">
              {fwResult.data.veris.map((v) => (
                <a
                  key={v.verisId}
                  href={ctidVerisUrl(v.verisId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-tooltip={`${v.count} techniques → ${v.verisId}`}
                  className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--purple-faint)] text-[var(--accent-purple)] border border-[var(--purple-dim)] hover:bg-[var(--purple-dim)] transition-colors"
                >
                  {v.verisId} ↗
                </a>
              ))}
            </div>
          </CollapsibleSection>
        )}

        {/* Cloud Controls — collapsed */}
        {fwResult.data?.cloud && fwResult.data.cloud.length > 0 && (
          <CollapsibleSection title="Cloud Security Controls" count={fwResult.data.cloud.length} defaultOpen={false}>
            <div className="flex flex-wrap gap-1.5">
              {fwResult.data.cloud.map((c) => (
                <a
                  key={`${c.provider}-${c.controlId}`}
                  href={ctidCloudUrl(c.provider, c.controlId)}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-tooltip={`${c.controlName} (${c.provider}) — ${c.count} techniques`}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--teal-faint)] text-[var(--accent-teal)] border border-[var(--teal-dim)] hover:bg-[var(--teal-dim)] transition-colors"
                >
                  <span className="uppercase text-[8px] opacity-60">{c.provider}</span>
                  {c.controlId} ↗
                </a>
              ))}
            </div>
          </CollapsibleSection>
        )}

        {/* Techniques — last, largest section */}
        {techniques.length > 0 && (
          <CollapsibleSection title="Techniques" count={techniques.length} defaultOpen>
            <TechniquesByTactic techniques={techniques} />
          </CollapsibleSection>
        )}

        {techniques.length === 0 && software.length === 0 && campaigns.length === 0 && (
          <p className="text-[var(--text-secondary)] text-sm py-4 text-center">
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
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-semibold text-[var(--text-primary)]">{campaign.name}</h2>
            <ExternalLinksButton type="campaign" attackId={campaign.attackId} name={campaign.name} />
          </div>
          <div className="flex items-center gap-2 mt-1">
            <span className="font-mono text-xs text-[var(--accent-blue)] bg-[var(--blue-faint)] border border-[var(--blue-dim)] px-2 py-0.5 rounded">
              {campaign.attackId}
            </span>
            <Badge label="campaign" variant="blue" />
            {campaign.firstSeen && (
              <span className="text-xs text-[var(--text-secondary)]">
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
              <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name}  useMap />
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* VERIS — collapsed */}
      {fwResult.data?.veris && fwResult.data.veris.length > 0 && (
        <CollapsibleSection title="VERIS Incident Categories" count={fwResult.data.veris.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1.5">
            {fwResult.data.veris.map((v) => (
              <a key={v.verisId} href={`https://center-for-threat-informed-defense.github.io/mappings-explorer/external/veris/attack-16.1/domain-enterprise/veris-1.4.0/capability-groups/${encodeURIComponent(v.verisId)}/`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--purple-faint)] text-[var(--accent-purple)] border border-[var(--purple-dim)] hover:bg-[var(--purple-dim)] transition-colors">
                {v.verisId} ↗
              </a>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Cloud Controls — collapsed */}
      {fwResult.data?.cloud && fwResult.data.cloud.length > 0 && (
        <CollapsibleSection title="Cloud Security Controls" count={fwResult.data.cloud.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1.5">
            {fwResult.data.cloud.map((c) => (
              <a key={`${c.provider}-${c.controlId}`} href={ctidCloudUrl(c.provider, c.controlId)} target="_blank" rel="noopener noreferrer" data-tooltip={`${c.controlName} (${c.provider})`} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--teal-faint)] text-[var(--accent-teal)] border border-[var(--teal-dim)] hover:bg-[var(--teal-dim)] transition-colors">
                <span className="uppercase text-[8px] opacity-60">{c.provider}</span>{c.controlId} ↗
              </a>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Techniques */}
      {techniques.length > 0 && (
        <CollapsibleSection title="Techniques Used" count={techniques.length} defaultOpen>
          <div className="flex flex-wrap gap-1.5">
            {techniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name}  useMap />
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
                <EntityLink type="software" attackId={s.attackId} name={s.name}  useMap />
                <Badge label={s.type} variant={s.type === 'malware' ? 'pink' : 'purple'} />
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {techniques.length === 0 && software.length === 0 && groups.length === 0 && (
        <p className="text-[var(--text-secondary)] text-sm py-4 text-center">
          No relationship data available for this campaign.
        </p>
      )}
    </div>
  );
}
