import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useTechnique, useFrameworks, useIntelligence } from '../../hooks/useApi';
import { useSector } from '../../contexts/SectorContext';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { VtLookupModal, VtButton } from '../shared/VtLookupModal';

// ── Level badge (reused pattern from TechniqueDetail) ─────────────────────────

const LEVEL_COLORS: Record<string, string> = {
  critical: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  high: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  medium: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  low: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
  informational: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return null;
  const cls = LEVEL_COLORS[level.toLowerCase()] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
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
    <div className="border border-[var(--border-color)] rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 bg-[var(--surface-card)] hover:bg-[var(--surface-base)] transition-colors text-left gap-3"
      >
        <div className="flex items-center gap-2">
          <span className="text-[var(--accent-teal)] w-4 h-4 shrink-0">{icon}</span>
          <span className="text-sm font-bold text-[var(--text-secondary)] uppercase tracking-wider">{label}</span>
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
        <div className="px-4 py-4 bg-[var(--surface-alt)] space-y-3">
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
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{prefix}</span>
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

const IconVt = (
  <svg viewBox="0 0 24 24" fill="currentColor" className="w-4 h-4">
    <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
  </svg>
);

// ── Main component ─────────────────────────────────────────────────────────────

interface TechniqueMapViewProps {
  attackId: string;
}

/** VT section with modal support */
function VtSection({ iocs, loading }: { iocs: Array<{ id: string; type: string; value: string; confidence: string | null; malware_family: string | null; first_seen_at: string | null; vt_malicious: number | null; vt_total: number | null; vt_verdict: string | null }>; loading: boolean }) {
  const [vtHash, setVtHash] = useState<string | null>(null);
  const vtIocs = iocs.filter((ioc) => ioc.confidence === 'sandbox_verified' || ioc.vt_verdict).slice(0, 5);

  if (vtIocs.length === 0 && !loading) return null;

  return (
    <>
      <MapCard label={`VirusTotal Sandboxing Report${vtIocs.length >= 5 ? ' (last 5)' : ''}`} icon={IconVt} count={vtIocs.length}>
        {vtIocs.length > 0 ? (
          <div className="space-y-1.5">
            {vtIocs.map((ioc) => (
              <div
                key={ioc.id}
                className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                {/* Verdict badge */}
                {ioc.vt_verdict === 'malicious' && ioc.vt_malicious != null && ioc.vt_total != null ? (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)] shrink-0 font-medium">
                    {ioc.vt_malicious}/{ioc.vt_total}
                  </span>
                ) : ioc.vt_verdict === 'clean' ? (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)] shrink-0 font-medium">
                    clean
                  </span>
                ) : (
                  <Badge label="sandbox" variant="blue" />
                )}
                {/* Confidence */}
                {ioc.confidence === 'sandbox_verified' && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded-full border bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)] shrink-0">
                    sandbox
                  </span>
                )}
                {/* Malware family */}
                {ioc.malware_family && (
                  <span className="text-[10px] text-[var(--accent-orange)] shrink-0">{ioc.malware_family}</span>
                )}
                {/* Hash (truncated) */}
                <span className="font-mono text-[10px] text-[var(--text-secondary)] truncate flex-1" title={ioc.value}>
                  {ioc.value.slice(0, 12)}...{ioc.value.slice(-6)}
                </span>
                {/* Date */}
                {ioc.first_seen_at && (
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                    {new Date(ioc.first_seen_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                  </span>
                )}
                {/* VT lookup button */}
                {ioc.type === 'hash' && (
                  <VtButton hash={ioc.value} onClick={() => setVtHash(ioc.value)} />
                )}
              </div>
            ))}
          </div>
        ) : (
          loading ? (
            <MapRow prefix="Hashes">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : null
        )}
      </MapCard>
      {vtHash && <VtLookupModal hash={vtHash} onClose={() => setVtHash(null)} />}
    </>
  );
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
      <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-8 justify-center">
        <span className="inline-block w-5 h-5 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
        Loading technique map...
      </div>
    );
  }

  if (techError || !technique) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
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
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">{technique.name}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-teal)] bg-[var(--teal-faint)] border border-[var(--teal-dim)] px-2 py-0.5 rounded">
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

      {/* THREAT REPORTS — first */}
      {(() => {
        const reports = intel?.reports ?? [];
        return (
          <MapCard label={`Threat Reports${reports.length >= 5 ? ' (last 5)' : ''}`} icon={IconResponse} count={reports.length}>
            {reports.length > 0 ? (
              <div className="space-y-1.5">
                {reports.slice(0, 5).map((r) => (
                  <a
                    key={r.id}
                    href={r.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors group"
                  >
                    <span className="text-xs text-[var(--text-primary)] group-hover:text-[var(--accent-teal)] flex-1 truncate">{r.title}</span>
                    <Badge label={r.source} variant="neutral" />
                    {r.published_at && (
                      <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                        {new Date(r.published_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                      </span>
                    )}
                  </a>
                ))}
              </div>
            ) : (
              intelLoading ? (
                <MapRow prefix="Reports">
                  <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
                </MapRow>
              ) : (
                <MapRow prefix="Reports">
                  <span className="text-xs text-[var(--text-secondary)]">No threat reports linked yet.</span>
                </MapRow>
              )
            )}
          </MapCard>
        );
      })()}

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
          <p className="text-xs text-[var(--text-secondary)]">No groups documented for this technique.</p>
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
          <>
            <MapRow prefix="Sigma Rules">
              <div className="flex flex-wrap gap-1.5">
                <Badge label={`${sigmaRules.length} rules`} variant="teal" />
                {Object.entries(sigmaByLevel).map(([lvl, count]) => (
                  <span key={lvl} className="flex items-center gap-1">
                    <span className="text-xs text-[var(--text-primary)] font-mono">{count}</span>
                    <LevelBadge level={lvl} />
                  </span>
                ))}
              </div>
            </MapRow>
            <div className="mt-1 space-y-1">
              {sigmaRules.slice(0, 5).map((rule) => (
                <Link
                  key={rule.sigma_id ?? rule.id}
                  to="/cti/sigma"
                  className="flex items-center gap-2 py-1 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors group"
                >
                  <LevelBadge level={rule.level} />
                  <span className="text-[11px] text-[var(--text-primary)] group-hover:text-[var(--accent-teal)] truncate flex-1">{rule.title}</span>
                </Link>
              ))}
              {sigmaRules.length > 5 && (
                <Link to="/cti/sigma" className="text-[10px] text-[var(--accent-teal)] hover:underline px-3">
                  +{sigmaRules.length - 5} more rules
                </Link>
              )}
            </div>
          </>
        ) : (
          intelLoading ? (
            <MapRow prefix="Sigma Rules">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="Sigma Rules">
              <span className="text-xs text-[var(--text-secondary)]">No sigma rules in feed yet.</span>
            </MapRow>
          )
        )}

        {technique.detection && (
          <div className="mt-2 pt-2 border-t border-[var(--border-color)]">
            <p className="text-xs text-[var(--text-secondary)] font-semibold uppercase tracking-wider mb-1">
              Detection Notes
            </p>
            <p className="text-xs text-[var(--text-secondary)] leading-relaxed line-clamp-4">
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
            <span className="text-xs text-[var(--text-secondary)]">No mitigations linked.</span>
          </MapRow>
        )}

        {nistControls.length > 0 ? (
          <MapRow prefix="NIST Controls">
            <div className="flex flex-wrap gap-1.5 max-h-40 overflow-y-auto">
              {nistControls.map((ctrl) => (
                <a
                  key={ctrl.controlId}
                  href={`https://csf.tools/reference/nist-sp-800-53/r5/${ctrl.controlId.split('-')[0].toLowerCase()}/${ctrl.controlId.toLowerCase()}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  title={ctrl.controlName ?? ctrl.controlId}
                  className="hover:opacity-80 transition-opacity"
                >
                  <Badge label={ctrl.controlId} variant="blue" />
                </a>
              ))}
            </div>
          </MapRow>
        ) : (
          fwLoading ? (
            <MapRow prefix="NIST Controls">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="NIST Controls">
              <span className="text-xs text-[var(--text-secondary)]">No NIST controls mapped yet.</span>
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
                <span className="font-mono text-xs text-[var(--accent-teal)] bg-[var(--teal-ghost)] border border-[var(--teal-dim)] px-1.5 py-0.5 rounded">
                  {act.engageId}
                </span>
                <span className="text-xs text-[var(--text-primary)]">{act.engageName}</span>
                {act.goal && <Badge label={act.goal} variant="orange" />}
              </div>
            ))}
          </MapRow>
        ) : (
          fwLoading ? (
            <MapRow prefix="MITRE Engage">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="MITRE Engage">
              <span className="text-xs text-[var(--text-secondary)]">No Engage activities mapped yet.</span>
            </MapRow>
          )
        )}
        {d3fendMappings.length > 0 ? (
          <MapRow prefix="D3FEND">
            {d3fendMappings.map((m) => (
              <div key={m.d3fend_id} className="flex items-center gap-1">
                <span className="font-mono text-xs text-[var(--accent-green)] bg-[var(--green-faint)] border border-[var(--green-dim)] px-1.5 py-0.5 rounded">
                  {m.d3fend_id}
                </span>
                <span className="text-xs text-[var(--text-primary)]">{m.d3fend_label}</span>
                {m.d3fend_tactic && <Badge label={m.d3fend_tactic} variant="green" />}
              </div>
            ))}
          </MapRow>
        ) : (
          intelLoading ? (
            <MapRow prefix="D3FEND">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="D3FEND">
              <span className="text-xs text-[var(--text-secondary)]">No D3FEND mappings yet.</span>
            </MapRow>
          )
        )}
        <MapRow prefix="RE&CT">
          <Link to="/frameworks/react" className="text-xs text-[var(--accent-teal)] hover:underline">
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
                  className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                >
                  <span className="font-mono text-xs text-[var(--accent-teal)] shrink-0">
                    #{test.test_number}
                  </span>
                  <span className="text-xs text-[var(--text-primary)] flex-1 truncate">{test.name}</span>
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
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="Atomic Red Team">
              <span className="text-xs text-[var(--text-secondary)]">No atomic tests in feed yet.</span>
            </MapRow>
          )
        )}
      </MapCard>

      {/* VIRUSTOTAL INTELLIGENCE */}
      <VtSection iocs={intel?.iocs ?? []} loading={intelLoading} />

    </div>
  );
}
