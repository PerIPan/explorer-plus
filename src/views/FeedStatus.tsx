'use client';
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useFeedStatus } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import type { FeedSyncStatus } from '../lib/types';

const SOURCE_LABELS: Record<string, string> = {
  otx: 'AlienVault OTX',
  abuse_ch: 'abuse.ch',
  cisa_kev: 'CISA KEV',
  rss: 'RSS Feeds',
  d3fend: 'D3FEND',
  nvd: 'NVD CVE Enrichment',
  virustotal: 'VirusTotal',
  matview_refresh: 'Matview refresh',
  cve_delta: 'CVE Delta Ingest',
  cve_products: 'CVE → Application enrichment',
  epss: 'EPSS',
  osv: 'OSV',
  csf: 'NIST CSF v2',
  ghsa: 'GHSA (full)',
  ghsa_delta: 'GHSA (delta)',
  sigma: 'Sigma Rules',
  atomic: 'Atomic Red Team',
  site_health: 'Site health (VT self-scan)',
};

/**
 * Short gray-text descriptions shown under each source label — one-liner
 * explaining what the feed ingests. Matches the user's mental model better
 * than the label alone.
 */
const SOURCE_DESCRIPTIONS: Record<string, string> = {
  otx: 'AlienVault OTX pulses — threat reports + IOCs',
  abuse_ch: 'ThreatFox + MalwareBazaar — IP/domain/hash IOCs',
  cisa_kev: 'Known Exploited Vulnerabilities — CVE flagging',
  rss: 'DFIR Report, Unit 42, Microsoft Security, Talos',
  d3fend: 'Defensive countermeasure mappings to ATT&CK',
  nvd: 'CVSS + CWE enrichment from NVD API',
  virustotal: 'Sandbox verdicts + malware family for hashes',
  matview_refresh: 'app_technique_groups + package_summary matviews',
  cve_delta: 'CVElistV5 git repo — last-48h delta of new CVEs + CVSS + affected products',
  cve_products: 'Retries NVD for CVEs missing CPE (vendor/product) data',
  epss: 'First.org exploit-probability scoring, daily refreshed',
  osv: 'OS, distro, kernel advisories — Linux, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, …',
  csf: 'NIST Cybersecurity Framework v2 subcategories + CRI Profile crosswalk',
  ghsa: 'GitHub Security Advisories — full corpus rebase (monthly)',
  ghsa_delta: 'GitHub Security Advisories — incremental delta (daily)',
  sigma: 'SigmaHQ detection rules — weekly refresh',
  atomic: 'Atomic Red Team adversary-emulation tests — weekly refresh',
  site_health: 'VirusTotal self-scan of mitre-explorer.org (weekly)',
};

function formatTimeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function StatusDot({ status }: { status: string }) {
  const colorMap: Record<string, string> = {
    success: 'bg-[#34d399]',
    running: 'bg-[#fbbf24] animate-pulse',
    error: 'bg-[var(--accent-orange)]',
  };
  return (
    <span
      className={`inline-block w-2.5 h-2.5 rounded-full ${colorMap[status] ?? 'bg-[var(--text-secondary)]'}`}
      title={status}
    />
  );
}

function StatusBadge({ status }: { status: string }) {
  const styleMap: Record<string, string> = {
    success: 'bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]',
    running: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
    error: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  };
  const classes = styleMap[status] ?? 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]';
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${classes}`}>
      {status}
    </span>
  );
}

interface FeedCardProps {
  feed: FeedSyncStatus;
}

/**
 * Compact single-row layout. Grid columns:
 *   [dot] [label + description]  [last-sync]  [status-badge]
 * Error messages render as an indented sub-row when present.
 */
function FeedCard({ feed }: FeedCardProps) {
  const description = SOURCE_DESCRIPTIONS[feed.source];
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md px-4 py-2.5">
      <div className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3">
        <StatusDot status={feed.status} />
        <div className="min-w-0">
          <div className="text-[var(--text-primary)] font-medium text-sm truncate">
            {SOURCE_LABELS[feed.source] ?? feed.source}
          </div>
          {description && (
            <div className="text-[11px] text-[var(--text-secondary)] truncate opacity-70">
              {description}
            </div>
          )}
        </div>
        <span className="text-xs text-[var(--text-secondary)] whitespace-nowrap">
          {formatTimeAgo(feed.lastSync)}
        </span>
        <StatusBadge status={feed.status} />
      </div>
      {feed.error && (
        <div className="mt-2 ml-6 text-[11px] text-[var(--accent-orange)] bg-[var(--orange-faint)] border border-[var(--orange-dim)] rounded px-2 py-1 font-mono break-words">
          {feed.error}
        </div>
      )}
    </div>
  );
}

const AUTO_ONLY_SOURCES = new Set(['nvd', 'virustotal']);

/** Placeholder row for sources not yet in the DB log */
function EmptyFeedCard({ source }: { source: string }) {
  const description = SOURCE_DESCRIPTIONS[source];
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md px-4 py-2.5">
      <div className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3">
        <span className="inline-block w-2.5 h-2.5 rounded-full bg-[var(--text-secondary)]" />
        <div className="min-w-0">
          <div className="text-[var(--text-primary)] font-medium text-sm truncate">
            {SOURCE_LABELS[source] ?? source}
          </div>
          {description && (
            <div className="text-[11px] text-[var(--text-secondary)] truncate opacity-70">
              {description}
            </div>
          )}
        </div>
        <span className="text-xs text-[var(--text-secondary)] whitespace-nowrap">—</span>
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]">
          {AUTO_ONLY_SOURCES.has(source) ? 'scheduled' : 'pending'}
        </span>
      </div>
    </div>
  );
}

const ALL_SOURCES = [
  'otx', 'abuse_ch', 'cisa_kev', 'rss',
  'nvd', 'virustotal',
  'cve_delta', 'cve_products',
  'epss', 'osv', 'csf',
  'ghsa', 'ghsa_delta', 'sigma', 'atomic',
  'matview_refresh', 'd3fend',
  'site_health',
];

export function FeedStatus() {

  const { data, refetch } = useFeedStatus();

  const feedMap = new Map<string, FeedSyncStatus>(
    (data?.data ?? []).map((f) => [f.source, f]),
  );

  /** Poll every 5s while any source is in running state */
  const hasRunning = (data?.data ?? []).some((f) => f.status === 'running');
  useEffect(() => {
    if (!hasRunning) return;
    const interval = setInterval(() => { void refetch(); }, 5000);
    return () => clearInterval(interval);
  }, [hasRunning, refetch]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Feed Status"
        subtitle="CTI ingestion pipeline health and manual sync controls"
      />

      <div className="space-y-2">
        {ALL_SOURCES.map((source) => {
          const feed = feedMap.get(source);
          return feed
            ? <FeedCard key={source} feed={feed} />
            : <EmptyFeedCard key={source} source={source} />;
        })}
      </div>

      {/* Framework sync status */}
      <FrameworkStatus />
    </div>
  );
}

interface FrameworkTable {
  key: string;
  label: string;
  description: string;
  /** If true, empty state is intentional — source data pending, not a sync failure */
  expectedEmpty?: boolean;
}

/** Populated automatically by Vercel crons or GitHub Actions. */
const AUTOMATED_TABLES: FrameworkTable[] = [
  { key: 'cve_details', label: 'CVE Details', description: 'CVElistV5 corpus with CVSS, CWE, KEV flag, EPSS enrichment' },
  { key: 'cve_weaknesses', label: 'CVE Weaknesses', description: 'CWE weakness categorisation per CVE' },
  { key: 'affected_products', label: 'Affected Products', description: 'CVE ↔ application edges with version ranges' },
  { key: 'applications', label: 'Applications (CVElistV5)', description: 'Vendor/product rows extracted from CVE CPE data' },
  { key: 'ghsa_advisories', label: 'GitHub Security Advisories', description: 'Reviewed OSS package advisories — npm, PyPI, Maven, Go, …' },
  { key: 'ghsa_weaknesses', label: 'GHSA CWE Mappings', description: 'CWE weakness categorisation per GHSA advisory' },
  { key: 'ghsa_packages', label: 'GHSA Affected Packages', description: 'Per-package vulnerable/fixed version ranges' },
  { key: 'packages', label: 'Packages (derived from GHSA)', description: 'Unique (ecosystem, package) pairs across 8 OSS ecosystems' },
  { key: 'osv_advisories', label: 'OSV Advisories (OS, distro, kernel)', description: 'Non-GHSA ecosystems — Linux, Debian, Ubuntu, Alpine, Android, OSS-Fuzz, …' },
  { key: 'osv_affected', label: 'OSV Affected Packages', description: 'Per-package version ranges for OSV advisories' },
  { key: 'csf_subcategories', label: 'NIST CSF v2 Subcategories', description: 'GV/ID/PR/DE/RS/RC functions — 23 subcategories from the 2024 release' },
  { key: 'csf_technique_mappings', label: 'NIST CSF v2 → ATT&CK', description: 'CRI Profile crosswalk: CSF subcategory → ATT&CK technique' },
  { key: 'csf_implementation_examples', label: 'NIST CSF v2 Examples', description: 'One-line implementation examples per CSF subcategory' },
  { key: 'csf_informative_references', label: 'NIST CSF v2 References', description: 'Informative references into NIST 800-53 r5 and ISO 27001:2022' },
  { key: 'defensive_mappings', label: 'D3FEND', description: 'Defensive countermeasures from the MITRE D3FEND knowledge graph' },
  { key: 'sigma_rules', label: 'Sigma Rules', description: '3,100+ detection rules from SigmaHQ with ATT&CK mappings' },
  { key: 'atomic_tests', label: 'Atomic Red Team', description: '1,770+ adversary-emulation tests (PowerShell/bash/batch)' },
];

/** Loaded once via Node scripts. Refresh means re-running the script. */
const REFERENCE_TABLES: FrameworkTable[] = [
  { key: 'owasp_top10', label: 'OWASP Top 10 (Web, ML, LLM)', description: '30 categories across 3 frameworks — CWEs, ATT&CK techniques, ATLAS techniques' },
  { key: 'nist_controls', label: 'NIST 800-53', description: '5,200+ security controls from NIST 800-53 r5 mapped to ATT&CK' },
  { key: 'engage_mappings', label: 'MITRE Engage', description: 'Adversary engagement activities — deception and engagement mappings' },
  { key: 'react_actions', label: 'RE&CT', description: 'ATC incident-response playbook actions — Identification, Containment, …' },
  { key: 'veris_mappings', label: 'VERIS', description: 'Verizon DBIR incident classification (Actor/Action/Asset/Attribute)' },
  { key: 'cloud_control_mappings', label: 'Cloud Controls (Azure + GCP)', description: 'Cloud provider security controls mapped to ATT&CK techniques' },
  { key: 'capec_mappings', label: 'CAPEC → ATT&CK Bridge', description: 'CWE → CAPEC → ATT&CK pivot, powers CVE→technique chain' },
  { key: 'capec_patterns', label: 'CAPEC Patterns (full taxonomy)', description: '615 attack patterns with prerequisites, skills, consequences, related patterns' },
  { key: 'capec_mitigations', label: 'CAPEC Mitigations', description: 'Per-pattern mitigation guidance from the CAPEC taxonomy' },
  { key: 'detection_strategies', label: 'Detection Strategies', description: 'ATT&CK v18 detection strategies — high-level detection intent' },
  { key: 'detection_analytics', label: 'Detection Analytics', description: 'Concrete analytics (pseudo-code / query logic) per detection strategy' },
  { key: 'external_actors', label: 'ETDA / ThaiCERT Actors', description: '514 external threat actors — country, motivation, MITRE group mapping' },
  { key: 'atlas_xrefs', label: 'ATLAS Cross-References', description: 'ATT&CK ↔ ATLAS technique cross-walks (AI/ML adversary TTPs)' },
  { key: 'ctid_mappings', label: 'CTID CVE → Technique', description: 'Hand-curated CVE to ATT&CK technique mappings from MITRE CTID' },
];

interface FrameworkStatusResponse {
  counts: Record<string, number>;
  ecosystemDrift?: { registered: number; inDb: number; unknown: string[] };
}

function FrameworkStatus() {
  const { data } = useQuery({
    queryKey: ['framework-counts'],
    queryFn: () => apiFetch<FrameworkStatusResponse>('/frameworks/status'),
    refetchInterval: 60_000,
  });

  const counts = data?.counts ?? {};
  const drift = data?.ecosystemDrift;
  return (
    <div className="space-y-6 mt-8">
      {drift && <EcosystemDriftRow drift={drift} />}
      <TableRowsSection title="Automated Data Tables" tables={AUTOMATED_TABLES} counts={counts} />
      <TableRowsSection title="Reference Data (Manual)" tables={REFERENCE_TABLES} counts={counts} />
    </div>
  );
}

function EcosystemDriftRow({
  drift,
}: {
  drift: { registered: number; inDb: number; unknown: string[] };
}) {
  const clean = drift.unknown.length === 0;
  const dotClass = clean ? 'bg-[var(--accent-green)]' : 'bg-[var(--accent-yellow)]';
  const badge = clean ? (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]">
      in sync
    </span>
  ) : (
    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]">
      drift
    </span>
  );
  return (
    <div>
      <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-3">
        Ecosystem Registry Coverage
      </h2>
      <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md px-4 py-2.5">
        <div className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3">
          <span className={`inline-block w-2.5 h-2.5 rounded-full ${dotClass}`} />
          <div className="min-w-0">
            <div className="text-[var(--text-primary)] font-medium text-sm truncate">
              src/lib/ecosystems.ts coverage
            </div>
            <div className="text-[11px] text-[var(--text-secondary)] truncate opacity-70">
              {clean
                ? `Every DB ecosystem has a registry entry — ${drift.registered} registered, ${drift.inDb} in DB`
                : `${drift.unknown.length} DB ecosystem${drift.unknown.length === 1 ? '' : 's'} missing from registry: ${drift.unknown.join(', ')}`}
            </div>
          </div>
          <span className="text-xs text-[var(--text-secondary)] whitespace-nowrap">
            {drift.registered}/{drift.inDb}
          </span>
          {badge}
        </div>
      </div>
    </div>
  );
}

function TableRowsSection({
  title,
  tables,
  counts,
}: {
  title: string;
  tables: FrameworkTable[];
  counts: Record<string, number>;
}) {
  const fmt = (n: number | undefined): string => (n == null ? '—' : n.toLocaleString());
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
        {title}
      </h2>
      <div className="space-y-2">
        {tables.map((fw) => {
          const count = counts[fw.key];
          const hasData = count != null && count > 0;
          const isPending = !hasData && fw.expectedEmpty;
          const dotClass = hasData
            ? 'bg-[var(--accent-green)]'
            : isPending
              ? 'bg-[var(--accent-yellow)]'
              : 'bg-[var(--text-secondary)]';
          const statusBadge = hasData ? (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]">
              synced
            </span>
          ) : isPending ? (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]">
              pending source
            </span>
          ) : (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]">
              pending
            </span>
          );
          return (
            <div
              key={fw.key}
              className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md px-4 py-2.5"
            >
              <div className="grid grid-cols-[auto_1fr_auto_auto] items-center gap-3">
                <span className={`inline-block w-2.5 h-2.5 rounded-full ${dotClass}`} />
                <div className="min-w-0">
                  <div className="text-[var(--text-primary)] font-medium text-sm truncate">
                    {fw.label}
                  </div>
                  <div className="text-[11px] text-[var(--text-secondary)] truncate opacity-70">
                    {fw.description}
                  </div>
                </div>
                <span className="hidden text-xs text-[var(--text-secondary)] whitespace-nowrap">
                  {fmt(count)}{hasData ? ' rows' : ''}
                </span>
                {statusBadge}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
