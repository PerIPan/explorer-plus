import { useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { apiFetch } from '../../lib/api';
import { useTechnique, useFrameworks, useIntelligence } from '../../hooks/useApi';
import { useSector } from '../../contexts/SectorContext';
import { useDomain } from '../../contexts/DomainContext';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { VtLookupModal, VtButton } from '../shared/VtLookupModal';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';
import { ctidCloudUrl, ctidVerisUrl } from '../../lib/urlSafety';
import { ExternalLinksButton } from '../shared/ExternalLinksButton';
import { formatDate } from '../../lib/formatDate';
import { DiamondLoader } from '../shared/FoldingDiamond';
import type { CloudControl } from '../../lib/types';

// ── Level badge ──────────────────────────────────────────────────────────────

const LEVEL_VARIANTS: Record<string, 'pink' | 'orange' | 'yellow' | 'blue' | 'green' | 'neutral'> = {
  critical: 'pink',
  high: 'orange',
  medium: 'yellow',
  low: 'blue',
  informational: 'green',
};

function LevelBadge({ level }: { level: string | null }) {
  if (!level) return null;
  return <Badge label={level} variant={LEVEL_VARIANTS[level.toLowerCase()] ?? 'neutral'} />;
}

// ── Collapsible card ───────────────────────────────────────────────────────────

interface MapCardProps {
  label: string;
  icon: React.ReactNode;
  count?: number;
  defaultOpen?: boolean;
  actionHref?: string;
  actionLabel?: string;
  children: React.ReactNode;
}

function MapCard({ label, icon, count, defaultOpen = true, actionHref, actionLabel, children }: MapCardProps) {
  const [open, setOpen] = useState(defaultOpen);

  return (
    <div className="border border-[var(--border-color)] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 bg-[var(--surface-card)]">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          className="flex items-center gap-3 flex-1 hover:opacity-80 transition-opacity text-left"
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
        {actionHref && (
          <a
            href={actionHref}
            target="_blank"
            rel="noopener noreferrer"
            className="text-[10px] text-[var(--accent-teal)] hover:underline shrink-0 ml-2"
          >
            {actionLabel ?? 'View all →'}
          </a>
        )}
      </div>
      {open && (
        <div className="px-3 md:px-4 py-4 bg-[var(--surface-alt)] space-y-5 overflow-hidden break-words">
          {children}
        </div>
      )}
    </div>
  );
}

/** Row inside a map card */
function MapRow({ prefix, prefixUrl, children }: { prefix: string; prefixUrl?: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[var(--text-secondary)] w-20 md:w-32 shrink-0 pt-0.5">
        {prefixUrl ? (
          <a href={prefixUrl} target="_blank" rel="noopener noreferrer" className="hover:text-[var(--accent-teal)] transition-colors" aria-label={`${prefix} (opens in new tab)`}>
            {prefix} <span aria-hidden="true">↗</span>
          </a>
        ) : prefix}
      </span>
      <div className="flex-1 min-w-0 flex flex-wrap gap-1.5">{children}</div>
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

const IconDatabase = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M4 7c0-1.657 3.582-3 8-3s8 1.343 8 3M4 7v10c0 1.657 3.582 3 8 3s8-1.343 8-3V7M4 7c0 1.657 3.582 3 8 3s8-1.343 8-3" />
  </svg>
);

const IconCloud = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z" />
  </svg>
);

const CLOUD_PROVIDER_COLORS: Record<string, string> = {
  azure: 'bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)]',
  gcp: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
  aws: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  m365: 'bg-[var(--teal-faint)] text-[var(--accent-teal)] border-[var(--teal-dim)]',
};

const CLOUD_PROVIDER_LABELS: Record<string, string> = {
  azure: 'Azure',
  gcp: 'GCP',
  aws: 'AWS',
  m365: 'M365',
};

/** Reusable popover shell for technique count circles — uses portal to escape overflow-hidden */
function TechniqueCountPopover({ count, open, onToggle, onClose, isLoading, techniques }: {
  count: number;
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  isLoading: boolean;
  techniques: Array<{ attackId: string; name: string }> | undefined;
}) {
  const btnRef = useRef<HTMLButtonElement>(null);
  const rect = open && btnRef.current ? btnRef.current.getBoundingClientRect() : null;

  return (
    <span className="shrink-0">
      <button
        ref={btnRef}
        type="button"
        onClick={onToggle}
        aria-label={`Show ${count} linked techniques`}
        aria-expanded={open}
        className="inline-flex items-center justify-center w-5 h-5 rounded-full text-[9px] font-bold bg-[var(--teal-faint)] text-[var(--accent-teal)] border border-[var(--teal-dim)] cursor-pointer hover:bg-[var(--teal-dim)] transition-colors"
      >
        {count}
      </button>
      {open && rect && createPortal(
        <>
          <div
            className="fixed inset-0 z-40"
            onClick={onClose}
            onKeyDown={(e) => { if (e.key === 'Escape') onClose(); }}
            role="button"
            aria-label="Close popover"
            tabIndex={-1}
          />
          <div
            className="fixed z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto"
            style={{ top: rect.bottom + 4, left: Math.max(8, rect.right - 240) }}
          >
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {techniques && (
              <div className="flex flex-col gap-1">
                {techniques.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
                ))}
              </div>
            )}
          </div>
        </>,
        document.body,
      )}
    </span>
  );
}

/** Clickable technique count popover for CVEs — lazy-loads techniques on click */
function CveTechniquePopover({ cveId, count }: { cveId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['cve-detail', cveId],
    queryFn: () => apiFetch<{ techniques: Array<{ attackId: string; name: string }> }>(`/cves/${cveId}`),
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });
  return (
    <TechniqueCountPopover
      count={count}
      open={open}
      onToggle={() => setOpen((prev) => !prev)}
      onClose={() => setOpen(false)}
      isLoading={isLoading}
      techniques={data?.techniques}
    />
  );
}

/** Clickable technique count popover for reports — lazy-loads techniques on click */
function ReportTechniquePopover({ reportId, count }: { reportId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['report-techniques', reportId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/feed/reports/${reportId}/techniques`),
    enabled: open,
    staleTime: 5 * 60 * 1000,
  });
  return (
    <TechniqueCountPopover
      count={count}
      open={open}
      onToggle={() => setOpen((prev) => !prev)}
      onClose={() => setOpen(false)}
      isLoading={isLoading}
      techniques={data?.data}
    />
  );
}

// ── Main component ─────────────────────────────────────────────────────────────

interface TechniqueMapViewProps {
  attackId: string;
}

/** VT section with modal support */
function VtSection({ iocs, loading }: { iocs: Array<{ id: string; type: string; value: string; source: string | null; confidence: string | null; malware_family: string | null; first_seen_at: string | null; vt_malicious: number | null; vt_total: number | null; vt_verdict: string | null; vt_file_type: string | null }>; loading: boolean }) {
  const [vtHash, setVtHash] = useState<string | null>(null);
  const vtIocs = iocs.filter((ioc) => ioc.confidence === 'sandbox_verified' || ioc.vt_verdict).slice(0, 5);

  if (vtIocs.length === 0 && !loading) return null;

  return (
    <>
      <MapCard label="VirusTotal Sandboxing Report" icon={IconVt} count={vtIocs.length}>
        {vtIocs.length > 0 ? (
          <div className="space-y-2">
            {vtIocs.map((ioc) => (
              <div
                key={ioc.id}
                className="flex items-center gap-3 py-2.5 px-4 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] min-w-0"
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
                {/* File type */}
                {ioc.vt_file_type && (
                  <span className="text-[9px] px-1.5 py-0.5 rounded border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)] shrink-0 truncate max-w-[80px]" title={ioc.vt_file_type}>
                    {ioc.vt_file_type}
                  </span>
                )}
                {/* Hash (truncated) */}
                <span className="font-mono text-[10px] text-[var(--text-secondary)] truncate" title={ioc.value}>
                  {ioc.value.slice(0, 12)}...{ioc.value.slice(-6)}
                </span>
                {/* VT lookup button — right after hash for easy access */}
                {ioc.type === 'hash' && (
                  <VtButton hash={ioc.value} onClick={() => setVtHash(ioc.value)} />
                )}
                {/* Date — pushed right */}
                <span className="flex-1" />
                {ioc.first_seen_at && (
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                    {formatDate(ioc.first_seen_at)}
                  </span>
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
  const { domainParam } = useDomain();
  const { data: technique, isLoading: techLoading, error: techError } = useTechnique(attackId, { ...sectorParam, ...domainParam });
  const { data: frameworks, isLoading: fwLoading } = useFrameworks(attackId);
  const { data: intel, isLoading: intelLoading } = useIntelligence(attackId);

  if (techLoading) {
    return <DiamondLoader text="Loading technique map..." />;
  }

  if (techError || !technique) {
    return (
      <div className="text-[var(--text-secondary)] text-sm py-8 text-center">
        Technique <span className="font-mono text-[var(--accent-teal)]">{attackId}</span> not found in the selected domain. Change the Domain selector to <strong>All</strong> to search across all domains.
      </div>
    );
  }

  // ── Derived values (memoized to avoid recalc on popover toggles) ─────────

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
  const reports = intel?.reports ?? [];
  const cves = intel?.cves ?? [];

  const groups = technique.groups ?? [];
  const campaigns = technique.campaigns ?? [];
  const mitigations = technique.mitigations ?? [];
  const dataComponents = technique.dataComponents ?? [];




  return (
    <div className="space-y-3 min-w-0 w-full overflow-hidden">
      {/* Technique header */}
      <div className="pb-1">
        <div className="flex items-center gap-2">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">{technique.name}</h2>
          <ExternalLinksButton type="technique" attackId={technique.attackId} name={technique.name} />
        </div>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-teal)] bg-[var(--teal-faint)] border border-[var(--teal-dim)] px-2 py-0.5 rounded">
            {technique.attackId}
          </span>
          {technique.domain && (
            <Badge label={technique.domain.replace('-attack', '')} variant="neutral" />
          )}
          {technique.maturity && (
            <Badge
              label={technique.maturity}
              variant={technique.maturity === 'realized' ? 'green' : technique.maturity === 'demonstrated' ? 'yellow' : 'orange'}
            />
          )}
          {technique.tactics?.map((tactic) => (
            <Badge key={tactic} label={tactic} variant="yellow" />
          ))}
          {technique.platforms?.map((p) => (
            <Badge key={p} label={p} variant="blue" />
          ))}
          {technique.atlasXrefs?.map((xref) => (
            <a
              key={xref.attackId}
              href={`/?entity=${xref.attackId}&tab=technique-map`}
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-[var(--purple-faint)] text-[var(--accent-purple)] border border-[var(--purple-dim)] hover:bg-[var(--purple-dim)] transition-colors"
            >
              {technique.domain === 'atlas-attack' ? 'ATT&CK:' : 'ATLAS:'} {xref.attackId} ↗
            </a>
          ))}
        </div>
      </div>

      {/* Description */}
      {technique.description && (
        <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4 overflow-hidden">
          <p
            className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap break-words"
            dangerouslySetInnerHTML={{ __html: sanitize(sanitizeMarkdown(technique.description)) }}
          />
        </div>
      )}


      {/* THREAT INTELLIGENCE — reports + CVEs */}
      <MapCard label="Threat Intelligence" icon={IconResponse} count={reports.length + cves.length}>
        {reports.length > 0 ? (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Reports</span>
              <a href="/cti/reports" target="_blank" rel="noopener noreferrer" className="ml-auto text-[10px] text-[var(--accent-teal)] hover:underline">All Reports →</a>
            </div>
            {reports.slice(0, 3).map((r) => (
              <div
                key={r.id}
                className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
              >
                <div className="flex items-center gap-1.5 flex-1 min-w-0">
                  {r.url ? (
                    <a
                      href={r.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs text-[var(--text-primary)] hover:text-[var(--accent-teal)] truncate"
                    >
                      {r.title}
                    </a>
                  ) : (
                    <span className="text-xs text-[var(--text-primary)] truncate">{r.title}</span>
                  )}
                  {r.technique_count > 0 && (
                    <ReportTechniquePopover reportId={r.id} count={r.technique_count} />
                  )}
                </div>
                <Badge label={r.source} variant="neutral" />
                {r.published_at && (
                  <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                    {formatDate(r.published_at)}
                  </span>
                )}
              </div>
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

        {/* CVEs */}
        {cves.length > 0 && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">Latest CVEs</span>
              {(intel?.affectedApps ?? []).length > 0 && (
                <Badge label={`${intel!.affectedApps.length} apps affected`} variant="blue" />
              )}
              <a
                href={`/cti/cves?technique=${encodeURIComponent(attackId)}&since=`}
                target="_blank"
                rel="noopener noreferrer"
                className="ml-auto text-[10px] text-[var(--accent-teal)] hover:underline"
              >
                All CVEs →
              </a>
            </div>
            {cves.map((cve) => {
              const sevColor = cve.cvss_severity === 'CRITICAL' ? 'pink' : cve.cvss_severity === 'HIGH' ? 'orange' : 'neutral';
              const desc = cve.description ?? cve.cve_id;
              const shortDesc = desc.length > 150 ? desc.slice(0, 150) + '...' : desc;
              return (
                <div
                  key={cve.cve_id}
                  className="flex items-center gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                >
                  <div className="flex items-center gap-1.5 flex-1 min-w-0">
                    <a
                      href={`/cti/cves?q=${encodeURIComponent(cve.cve_id)}&since=`}
                      className="text-xs text-[var(--text-primary)] hover:text-[var(--accent-teal)] truncate"
                    >
                      {shortDesc}
                    </a>
                    {cve.is_kev && <Badge label="KEV" variant="orange" />}
                  </div>
                  {cve.cvss_severity && <Badge label={cve.cvss_severity} variant={sevColor as 'pink' | 'orange' | 'neutral'} />}
                  <span className="font-mono text-[10px] text-[var(--accent-pink)] shrink-0">{cve.cve_id}</span>
                  {cve.published_at && (
                    <span className="text-[10px] text-[var(--text-secondary)] shrink-0">
                      {formatDate(cve.published_at)}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </MapCard>

      {/* WHO USES IT */}
      <MapCard label="Who Uses It" icon={IconPeople} count={groups.length + campaigns.length}>
        {groups.length > 0 ? (
          <MapRow prefix="Groups">
            <div className="flex flex-wrap gap-1.5 max-h-32 overflow-y-auto">
              {groups.map((g) => (
                <EntityLink key={g.attackId} type="group" attackId={g.attackId} name={g.name} useMap />
              ))}
            </div>
          </MapRow>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No groups documented for this technique.</p>
        )}
        {campaigns.length > 0 && (
          <MapRow prefix="Campaigns">
            {campaigns.map((c) => (
              <EntityLink key={c.attackId} type="campaign" attackId={c.attackId} name={c.name} useMap />
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
                  useMap
                />
                <Badge label={dc.componentName} variant="neutral" />
              </div>
            ))}
          </MapRow>
        ) : null}

        {/* Detection Strategies */}
        {intel?.detectionStrategies && intel.detectionStrategies.length > 0 && (
          <div className="space-y-2 mt-2">
            <span className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Detection Strategies ({intel.detectionStrategies.length})
            </span>
            {intel.detectionStrategies.map((ds: { det_id: string; name: string; analytics: Array<{ analytic_id: string; name: string; description: string | null; platforms: string[] }> }) => (
              <details key={ds.det_id} className="group rounded-md border border-[var(--border-color)] bg-[var(--surface-card)] overflow-hidden">
                <summary className="flex items-center gap-2 px-3 py-1.5 cursor-pointer hover:bg-[var(--teal-ghost)] transition-colors text-xs">
                  <svg className="w-2.5 h-2.5 text-[var(--text-secondary)] transition-transform group-open:rotate-90 shrink-0" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  <a
                    href={`https://attack.mitre.org/detectionstrategies/${ds.det_id}/`}
                    target="_blank"
                    rel="noopener noreferrer"
                    onClick={(e) => e.stopPropagation()}
                    className="font-mono text-[var(--accent-teal)] hover:underline shrink-0"
                  >
                    {ds.det_id}
                  </a>
                  <span className="text-[var(--text-primary)] truncate">{ds.name.replace(/^Detection Strategy for /, '')}</span>
                  {ds.analytics.length > 0 && (
                    <Badge label={`${ds.analytics.length} analytics`} variant="blue" />
                  )}
                </summary>
                {ds.analytics.length > 0 && (
                  <div className="px-3 pb-2 pt-1 border-t border-[var(--border-color)] space-y-1.5">
                    {ds.analytics.map((an) => (
                      <div key={an.analytic_id} className="py-1 px-2 rounded bg-[var(--surface-alt)] text-[11px]">
                        <div className="flex items-center gap-2">
                          <a
                            href={`https://attack.mitre.org/detectionstrategies/${ds.det_id}/#${an.analytic_id}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-[10px] text-[var(--accent-blue)] hover:underline shrink-0"
                          >
                            {an.analytic_id}
                          </a>
                          {an.platforms?.map((p) => (
                            <span key={p} className="text-[9px] text-[var(--text-secondary)] px-1 py-0.5 rounded border border-[var(--border-color)] shrink-0">{p}</span>
                          ))}
                        </div>
                        {an.description && (
                          <p className="text-[var(--text-secondary)] mt-0.5 line-clamp-3">{an.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </details>
            ))}
          </div>
        )}

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
                <a
                  key={rule.sigma_id ?? rule.id}
                  href={`/cti/sigma?technique=${attackId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 py-1 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)] hover:border-[var(--teal-dim)] transition-colors group"
                >
                  <LevelBadge level={rule.level} />
                  <span className="text-[11px] text-[var(--text-primary)] group-hover:text-[var(--accent-teal)] truncate flex-1">{rule.title}</span>
                </a>
              ))}
              {sigmaRules.length > 5 && (
                <a href={`/cti/sigma?technique=${attackId}`} target="_blank" rel="noopener noreferrer" className="text-[10px] text-[var(--accent-teal)] hover:underline px-3">
                  +{sigmaRules.length - 5} more rules
                </a>
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
              <EntityLink key={m.attackId} type="mitigation" attackId={m.attackId} name={m.name} useMap />
            ))}
          </MapRow>
        ) : (
          <MapRow prefix="Mitigations">
            <span className="text-xs text-[var(--text-secondary)]">No mitigations linked.</span>
          </MapRow>
        )}

        {nistControls.length > 0 ? (
          <MapRow prefix="NIST 800-53">
            <div className="space-y-1 max-h-48 overflow-y-auto w-full">
              {nistControls.map((ctrl) => (
                <a
                  key={ctrl.controlId}
                  href={`https://csf.tools/reference/nist-sp-800-53/r5/${ctrl.controlId.split('-')[0].toLowerCase()}/${ctrl.controlId.replace(/-0+/g, '-').toLowerCase()}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-2 py-1 px-2 rounded hover:bg-[var(--teal-ghost)] transition-colors group"
                >
                  <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-[var(--green-faint)] text-[var(--accent-green)] border border-[var(--green-dim)] shrink-0">{ctrl.controlId}</span>
                  <span className="text-xs text-[var(--text-primary)] group-hover:text-[var(--accent-teal)]">{ctrl.controlName ?? ctrl.controlId}</span>
                  {ctrl.controlFamily && <span className="text-[9px] text-[var(--text-secondary)] shrink-0">({ctrl.controlFamily})</span>}
                  <span className="text-[9px] text-[var(--text-secondary)] shrink-0 opacity-0 group-hover:opacity-100 ml-auto">↗</span>
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

      {/* OWASP RISK CATEGORIES */}
      {(() => {
        const owaspCats = frameworks?.owasp ?? [];
        return (
          <MapCard label="OWASP Risk Categories" icon={IconShield} count={owaspCats.length}>
            {owaspCats.length > 0 ? (
              <MapRow prefix="OWASP">
                <div className="flex flex-wrap gap-1.5">
                  {owaspCats.map((cat) => (
                    <EntityLink
                      key={`${cat.categoryId}-${cat.framework}`}
                      type="owasp"
                      attackId={cat.categoryId}
                      name={`${cat.name} (${cat.framework})`}
                    />
                  ))}
                </div>
              </MapRow>
            ) : fwLoading ? (
              <MapRow prefix="OWASP">
                <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
              </MapRow>
            ) : (
              <MapRow prefix="OWASP">
                <span className="text-xs text-[var(--text-secondary)]">No OWASP categories mapped.</span>
              </MapRow>
            )}
          </MapCard>
        );
      })()}

      {/* HOW TO RESPOND */}
      <MapCard label="How to Respond" icon={IconResponse}
        count={engageActivities.length + d3fendMappings.length}
      >
        {engageActivities.length > 0 ? (
          <MapRow prefix="MITRE Engage" prefixUrl="https://engage.mitre.org/">
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
            <MapRow prefix="MITRE Engage" prefixUrl="https://engage.mitre.org/">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="MITRE Engage" prefixUrl="https://engage.mitre.org/">
              <span className="text-xs text-[var(--text-secondary)]">No Engage activities mapped yet.</span>
            </MapRow>
          )
        )}
        {d3fendMappings.length > 0 ? (
          <MapRow prefix="D3FEND" prefixUrl="https://d3fend.mitre.org/">
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
            <MapRow prefix="D3FEND" prefixUrl="https://d3fend.mitre.org/">
              <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
            </MapRow>
          ) : (
            <MapRow prefix="D3FEND" prefixUrl="https://d3fend.mitre.org/">
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

      {/* PROCEDURES */}
      {(() => {
        const procedures = groups.filter((g) => g.procedure);
        if (procedures.length === 0) return null;
        return (
          <MapCard label="Procedures" icon={IconPeople} count={procedures.length} defaultOpen={false}>
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {procedures.map((g) => (
                <div key={g.attackId} className="py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]">
                  <div className="flex items-center gap-2 mb-1">
                    <EntityLink type="group" attackId={g.attackId} name={g.name} useMap />
                  </div>
                  <p
                    className="text-[11px] text-[var(--text-secondary)] leading-relaxed break-words"
                    dangerouslySetInnerHTML={{ __html: sanitize(sanitizeMarkdown(g.procedure ?? '')) }}
                  />
                </div>
              ))}
            </div>
          </MapCard>
        );
      })()}

      {/* HOW TO TEST */}
      <MapCard label="How to Test" icon={IconTest}
        count={atomicTests.length}
      >
        {atomicTests.length > 0 ? (
          <>
            <MapRow prefix="Atomic Red Team">
              <a
                href={`/frameworks/atomic?q=${attackId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-medium text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
              >
                view all ↗
              </a>
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
        <MapRow prefix="MITRE Caldera" prefixUrl="https://caldera.mitre.org/">
          <span className="text-xs text-[var(--text-secondary)]">adversary emulation platform</span>
        </MapRow>
      </MapCard>

      {/* AFFECTED APPLICATIONS */}
      {(intel?.affectedApps ?? []).length > 0 && (
        <MapCard label="Affected Applications" icon={IconDatabase} count={intel!.affectedApps.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto" tabIndex={0} aria-label="Affected applications">
            {intel!.affectedApps.map((app) => (
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
        </MapCard>
      )}

      {/* VIRUSTOTAL INTELLIGENCE */}
      <VtSection iocs={intel?.iocs ?? []} loading={intelLoading} />

      {/* VERIS */}
      {(() => {
        const veris = frameworks?.verisCategories ?? [];
        return (
          <MapCard label="VERIS Categories" icon={IconDatabase} count={veris.length} defaultOpen={false}>
            {veris.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 max-h-48 overflow-y-auto">
                {veris.map((v) => (
                  <a
                    key={v.verisId}
                    href={ctidVerisUrl(v.verisId)}
                    target="_blank"
                    rel="noopener noreferrer"
                    title={`View ${v.verisId} on CTID Mappings Explorer`}
                    className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-medium bg-[var(--purple-faint)] text-[var(--accent-purple)] border border-[var(--purple-dim)] hover:bg-[var(--purple-dim)] transition-colors"
                  >
                    {v.verisId} ↗
                  </a>
                ))}
              </div>
            ) : (
              fwLoading ? (
                <MapRow prefix="VERIS">
                  <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
                </MapRow>
              ) : (
                <MapRow prefix="VERIS">
                  <span className="text-xs text-[var(--text-secondary)]">No VERIS mappings yet. Run sync-frameworks.mjs to populate.</span>
                </MapRow>
              )
            )}
          </MapCard>
        );
      })()}

      {/* CLOUD CONTROLS */}
      {(() => {
        const cloud: CloudControl[] = frameworks?.cloudControls ?? [];
        const providers = Array.from(new Set(cloud.map((c) => c.provider))).sort();
        return (
          <MapCard label="Cloud Security Controls" icon={IconCloud} count={cloud.length} defaultOpen={false}>
            {cloud.length > 0 ? (
              <div className="space-y-3">
                {providers.map((p) => {
                  const ctrls = cloud.filter((c) => c.provider === p);
                  const colorCls =
                    CLOUD_PROVIDER_COLORS[p] ??
                    'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
                  return (
                    <div key={p}>
                      <div className="flex items-center gap-2 mb-1.5">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${colorCls}`}>
                          {CLOUD_PROVIDER_LABELS[p] ?? p.toUpperCase()}
                        </span>
                        <span className="text-xs text-[var(--text-secondary)]">{ctrls.length} controls</span>
                      </div>
                      <div className="space-y-1">
                        {ctrls.slice(0, 8).map((ctrl) => (
                          <div
                            key={`${ctrl.provider}-${ctrl.controlId}`}
                            className="flex items-start gap-2 py-1.5 px-3 rounded-md bg-[var(--surface-card)] border border-[var(--border-color)]"
                          >
                            <a
                              href={ctidCloudUrl(ctrl.provider, ctrl.controlId)}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-xs text-[var(--accent-teal)] shrink-0 mt-0.5 min-w-[180px] hover:underline"
                              title={`View ${ctrl.controlId} on CTID Mappings Explorer`}
                            >
                              {ctrl.controlId} ↗
                            </a>
                            <span className="text-xs text-[var(--text-primary)] flex-1" title={ctrl.controlName}>
                              {ctrl.controlName}
                            </span>
                            {ctrl.mappingType && (
                              <span className="text-[10px] font-medium text-[var(--text-secondary)] shrink-0 px-1.5 py-0.5 rounded bg-[var(--surface-alt)] border border-[var(--border-color)]">{ctrl.mappingType}</span>
                            )}
                          </div>
                        ))}
                        {ctrls.length > 8 && (
                          <span className="text-[10px] text-[var(--accent-teal)] px-3">
                            +{ctrls.length - 8} more
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              fwLoading ? (
                <MapRow prefix="Cloud">
                  <span className="text-xs text-[var(--text-secondary)] italic">Loading...</span>
                </MapRow>
              ) : (
                <MapRow prefix="Cloud">
                  <span className="text-xs text-[var(--text-secondary)]">No cloud control mappings yet. Run sync-frameworks.mjs to populate.</span>
                </MapRow>
              )
            )}
          </MapCard>
        );
      })()}

    </div>
  );
}
