import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTechnique, useFrameworks, useIntelligence } from '../../hooks/useApi';
import { useSector } from '../../contexts/SectorContext';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';

// ── Level badge (reused pattern from TechniqueDetail) ─────────────────────────

const LEVEL_COLORS: Record<string, string> = {
  critical: 'bg-[#f472b618] text-[#f472b6] border-[#f472b633]',
  high: 'bg-[#f9731618] text-[#f97316] border-[#f9731633]',
  medium: 'bg-[#fbbf2418] text-[#fbbf24] border-[#fbbf2433]',
  low: 'bg-[#60a5fa18] text-[#60a5fa] border-[#60a5fa33]',
  informational: 'bg-[#34d39918] text-[#34d399] border-[#34d39933]',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return null;
  const cls = LEVEL_COLORS[level.toLowerCase()] ?? 'bg-[#ffffff08] text-[#8892b0] border-[#2a2a4a]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${cls}`}>
      {level}
    </span>
  );
}

// ── Collapsible card ───────────────────────────────────────────────────────────

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
    <div className="border border-[#2a2a4a] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[#16213e] hover:bg-[#1a2a4a] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2">
          <span className="text-[#64ffda] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[#a8b2d8] uppercase tracking-wider">{label}</span>
          {count !== undefined && (
            <span className="text-xs text-[#8892b0]">({count})</span>
          )}
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
        <div className="px-4 py-4 bg-[#0f1929] space-y-3">
          {children}
        </div>
      )}
    </div>
  );
}

/** Row inside a map card */
function MapRow({ prefix, children }: { prefix: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[#8892b0] w-32 shrink-0 pt-0.5">{prefix}</span>
      <div className="flex-1 flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

const IconPeople = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M17 20h5v-2a4 4 0 00-5-3.87M9 20H4v-2a4 4 0 015-3.87m6 5.87v-2a6 6 0 00-12 0v2m6-6a4 4 0 110-8 4 4 0 010 8z" />
  </svg>
);

const IconEye = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
  </svg>
);

const IconShield = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
  </svg>
);

const IconResponse = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
  </svg>
);

const IconTest = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
  </svg>
);

// ── Main component ─────────────────────────────────────────────────────────────

interface TechniqueMapViewProps {
  attackId: string;
}

/**
 * Structured defensive/offensive overview of a technique:
 * who uses it, how to detect, prevent, respond, and test.
 */
export function TechniqueMapView({ attackId }: TechniqueMapViewProps) {
  const { sectorParam } = useSector();
  const { data: technique, isLoading: techLoading, error: techError } = useTechnique(attackId, sectorParam);
  const { data: frameworks, isLoading: fwLoading } = useFrameworks(attackId);
  const { data: intel, isLoading: intelLoading } = useIntelligence(attackId);

  if (techLoading) {
    return (
      <div className="flex items-center gap-2 text-[#8892b0] text-sm py-8 justify-center">
        <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin" />
        Loading technique map...
      </div>
    );
  }

  if (techError || !technique) {
    return (
      <div className="text-[#f97316] text-sm py-8 text-center">
        Failed to load technique data.
      </div>
    );
  }

  // ── Derived counts for sigma rules ────────────────────────────────────────

  const sigmaRules = intel?.sigmaRules ?? [];
  const sigmaByLevel = sigmaRules.reduce<Record<string, number>>((acc, r) => {
    const lvl = r.level?.toLowerCase() ?? 'unknown';
    acc[lvl] = (acc[lvl] ?? 0) + 1;
    return acc;
  }, {});

  const atomicTests = intel?.atomicTests ?? [];
  const atomicPlatforms = Array.from(
    new Set(atomicTests.flatMap((t) => t.platforms ?? []))
  );

  const nistControls = frameworks?.nist ?? [];
  const engageActivities = frameworks?.engage ?? [];
  const d3fendMappings = intel?.defensiveMappings ?? [];

  const groups = technique.groups ?? [];
  const campaigns = technique.campaigns ?? [];
  const mitigations = technique.mitigations ?? [];
  const dataComponents = technique.dataComponents ?? [];

  // Visible group slice (show up to 6, then "+N more")
  
  const visibleGroups = groups;
  

  return (
    <div className="space-y-3">
      {/* Technique header */}
      <div className="pb-1">
        <h2 className="text-lg font-semibold text-[#ccd6f6]">{technique.name}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[#64ffda] bg-[#64ffda18] border border-[#64ffda33] px-2 py-0.5 rounded">
            {technique.attackId}
          </span>
          {technique.tactics?.map((tactic) => (
            <Badge key={tactic} label={tactic} variant="yellow" />
          ))}
          {technique.platforms?.map((p) => (
            <Badge key={p} label={p} variant="blue" />
          ))}
        </div>
      </div>

      {/* WHO USES IT */}
      <MapCard label="Who Uses It" icon={IconPeople} count={groups.length + campaigns.length}>
        {groups.length > 0 ? (
          <MapRow prefix="Groups">
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
              {visibleGroups.map((g) => (
                <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} />
              ))}
            </div>
          </MapRow>
        ) : (
          <p className="text-xs text-[#8892b0]">No groups documented for this technique.</p>
        )}
        {campaigns.length > 0 && (
          <MapRow prefix="Campaigns">
            {campaigns.map((c) => (
              <EntityLink key={c.attackId} type="campaign" attackId={c.attackId} name={c.name} />
            ))}
          </MapRow>
        )}
      </MapCard>

      {/* HOW TO DETECT */}
      <MapCard label="How to Detect" icon={IconEye}
        count={dataComponents.length + sigmaRules.length}
      >
        {dataComponents.length > 0 ? (
          <MapRow prefix="Data Sources">
            {dataComponents.map((dc, i) => (
              <div key={i} className="flex items-center gap-1">
                <EntityLink
                  type="data_source"
                  attackId={dc.dataSourceAttackId}
                  name={dc.dataSourceName}
                />
                <Badge label={dc.componentName} variant="pink" />
              </div>
            ))}
          </MapRow>
        ) : null}

        {sigmaRules.length > 0 ? (
          <MapRow prefix="Sigma Rules">
            <div className="flex flex-wrap gap-1.5">
              <Badge label={`${sigmaRules.length} rules`} variant="teal" />
              {Object.entries(sigmaByLevel).map(([lvl, count]) => (
                <span key={lvl} className="flex items-center gap-1">
                  <span className="text-xs text-[#ccd6f6] font-mono">{count}</span>
                  <LevelBadge level={lvl} />
                </span>
              ))}
            </div>
          </MapRow>
        ) : (
          intelLoading ? (
            <MapRow prefix="Sigma Rules">
              <span className="text-xs text-[#8892b0] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="Sigma Rules">
              <span className="text-xs text-[#8892b0]">No sigma rules in feed yet.</span>
            </MapRow>
          )
        )}

        {technique.detection && (
          <div className="mt-2 pt-2 border-t border-[#2a2a4a]">
            <p className="text-xs text-[#8892b0] font-semibold uppercase tracking-wider mb-1">
              Detection Notes
            </p>
            <p className="text-xs text-[#a8b2d8] leading-relaxed line-clamp-4">
              {technique.detection}
            </p>
          </div>
        )}
      </MapCard>

      {/* HOW TO PREVENT */}
      <MapCard label="How to Prevent" icon={IconShield}
        count={mitigations.length + nistControls.length}
      >
        {mitigations.length > 0 ? (
          <MapRow prefix="Mitigations">
            {mitigations.map((m) => (
              <EntityLink key={m.attackId} type="mitigation" attackId={m.attackId} name={m.name} />
            ))}
          </MapRow>
        ) : (
          <MapRow prefix="Mitigations">
            <span className="text-xs text-[#8892b0]">No mitigations linked.</span>
          </MapRow>
        )}

        {nistControls.length > 0 ? (
          <MapRow prefix="NIST Controls">
            <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
              {nistControls.map((ctrl) => (
                <Badge key={ctrl.controlId} label={ctrl.controlId} variant="blue" />
              ))}
            </div>
          </MapRow>
        ) : (
          fwLoading ? (
            <MapRow prefix="NIST Controls">
              <span className="text-xs text-[#8892b0] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="NIST Controls">
              <span className="text-xs text-[#8892b0]">No NIST controls mapped yet.</span>
            </MapRow>
          )
        )}
      </MapCard>

      {/* HOW TO RESPOND */}
      <MapCard label="How to Respond" icon={IconResponse}
        count={engageActivities.length + d3fendMappings.length}
      >
        {engageActivities.length > 0 ? (
          <MapRow prefix="MITRE Engage">
            {engageActivities.map((act) => (
              <div key={act.engageId} className="flex items-center gap-1">
                <span className="font-mono text-xs text-[#64ffda] bg-[#64ffda0a] border border-[#64ffda22] px-1.5 py-0.5 rounded">
                  {act.engageId}
                </span>
                <span className="text-xs text-[#ccd6f6]">{act.engageName}</span>
                {act.goal && <Badge label={act.goal} variant="orange" />}
              </div>
            ))}
          </MapRow>
        ) : (
          fwLoading ? (
            <MapRow prefix="MITRE Engage">
              <span className="text-xs text-[#8892b0] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="MITRE Engage">
              <span className="text-xs text-[#8892b0]">No Engage activities mapped yet.</span>
            </MapRow>
          )
        )}
        {d3fendMappings.length > 0 ? (
          <MapRow prefix="D3FEND">
            {d3fendMappings.map((m) => (
              <div key={m.d3fend_id} className="flex items-center gap-1">
                <span className="font-mono text-xs text-[#34d399] bg-[#34d3990a] border border-[#34d39922] px-1.5 py-0.5 rounded">
                  {m.d3fend_id}
                </span>
                <span className="text-xs text-[#ccd6f6]">{m.d3fend_label}</span>
                {m.d3fend_tactic && <Badge label={m.d3fend_tactic} variant="green" />}
              </div>
            ))}
          </MapRow>
        ) : (
          intelLoading ? (
            <MapRow prefix="D3FEND">
              <span className="text-xs text-[#8892b0] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="D3FEND">
              <span className="text-xs text-[#8892b0]">No D3FEND mappings yet.</span>
            </MapRow>
          )
        )}
        <MapRow prefix="RE&CT">
          <Link to="/frameworks/react" className="text-xs text-[#64ffda] hover:underline">
            Browse response actions
          </Link>
        </MapRow>
      </MapCard>

      {/* HOW TO TEST */}
      <MapCard label="How to Test" icon={IconTest}
        count={atomicTests.length}
      >
        {atomicTests.length > 0 ? (
          <>
            <MapRow prefix="Atomic Red Team">
              <Badge label={`${atomicTests.length} tests`} variant="green" />
              {atomicPlatforms.map((p) => (
                <Badge key={p} label={p} variant="blue" />
              ))}
            </MapRow>
            <div className="mt-1 space-y-1.5">
              {atomicTests.map((test) => (
                <div
                  key={test.id}
                  className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a]"
                >
                  <span className="font-mono text-xs text-[#64ffda] shrink-0">
                    #{test.test_number}
                  </span>
                  <span className="text-xs text-[#ccd6f6] flex-1 truncate">{test.name}</span>
                  {test.executor_type && (
                    <Badge label={test.executor_type} variant="purple" />
                  )}
                </div>
              ))}
            </div>
          </>
        ) : (
          intelLoading ? (
            <MapRow prefix="Atomic Red Team">
              <span className="text-xs text-[#8892b0] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="Atomic Red Team">
              <span className="text-xs text-[#8892b0]">No atomic tests in feed yet.</span>
            </MapRow>
          )
        )}
      </MapCard>

      {/* THREAT REPORTS */}
      {(() => {
        const reports = intel?.reports ?? [];
        return (
          <MapCard label="Threat Reports" icon={IconResponse} count={reports.length}>
            {reports.length > 0 ? (
              <div className="space-y-1.5">
                {reports.map((r) => (
                  <a
                    key={r.id}
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[#16213e] border border-[#2a2a4a] hover:border-[#64ffda33] transition-colors group"
                  >
                    <span className="text-xs text-[#ccd6f6] group-hover:text-[#64ffda] flex-1 truncate">{r.title}</span>
                    <Badge label={r.source} variant="neutral" />
                    {r.published_at && (
                      <span className="text-[10px] text-[#8892b0] shrink-0">
                        {new Date(r.published_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                      </span>
                    )}
                  </a>
                ))}
              </div>
            ) : (
              intelLoading ? (
                <MapRow prefix="Reports">
                  <span className="text-xs text-[#8892b0] italic">Loading...</span>
                </MapRow>
              ) : (
                <MapRow prefix="Reports">
                  <span className="text-xs text-[#8892b0]">No threat reports linked yet.</span>
                </MapRow>
              )
            )}
          </MapCard>
        );
      })()}
    </div>
  );
}
