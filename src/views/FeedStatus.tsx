'use client';
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useFeedStatus } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import type { FeedSyncStatus } from '../lib/types';
import { FEED_SOURCES, MANUAL_SOURCES, AUTOMATED_TABLES, REFERENCE_TABLES } from '../lib/feeds';
import type { FrameworkTable } from '../lib/feeds';

const SOURCE_LABELS: Record<string, string> = {
  attack_update: 'MITRE ATT&CK (STIX)',
  ics_assets: 'ATT&CK for ICS assets',
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
  scf: 'SCF (Secure Controls Framework)',
  cti_heat_refresh: 'CTI heat refresh (compliance badges)',
};

/**
 * Short gray-text descriptions shown under each source label — one-liner
 * explaining what the feed ingests. Matches the user's mental model better
 * than the label alone.
 */
const SOURCE_DESCRIPTIONS: Record<string, string> = {
  attack_update: 'Enterprise, ICS, Mobile and ATLAS objects from the MITRE STIX bundles',
  ics_assets: 'The 18 ATT&CK for ICS assets and the techniques that target each',
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
  scf: 'Secure Controls Framework 2026.2 XLSX — 1,534 controls × 254 framework mappings, ingested twice a year (Jan/Jul)',
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
          {MANUAL_SOURCES.has(feed.source) && (
            <span
              className="mr-2 rounded border border-[var(--border-color)] px-1.5 py-px text-[10px] font-medium uppercase tracking-wider"
              title="Run by hand — no schedule. An old timestamp here is not a missed run."
            >
              manual
            </span>
          )}
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
          {MANUAL_SOURCES.has(source) ? 'manual' : AUTO_ONLY_SOURCES.has(source) ? 'scheduled' : 'pending'}
        </span>
      </div>
    </div>
  );
}

export function FeedStatus() {

  const { data, refetch } = useFeedStatus();

  const feedMap = new Map<string, FeedSyncStatus>(
    (data?.data ?? []).map((f) => [f.source, f]),
  );

  /** Poll every 30s while a sync is running (was 5s) — enough for progress,
      and bounded so a stuck "running" state can't pin Neon awake. */
  const hasRunning = (data?.data ?? []).some((f) => f.status === 'running');
  useEffect(() => {
    if (!hasRunning) return;
    const interval = setInterval(() => { void refetch(); }, 30_000);
    return () => clearInterval(interval);
  }, [hasRunning, refetch]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Feed Status"
        subtitle="CTI ingestion pipeline health and manual sync controls"
      />

      <div className="space-y-2">
        {FEED_SOURCES.map((source) => {
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


/** Populated automatically by Vercel crons or GitHub Actions. */

/** Loaded once via Node scripts. Refresh means re-running the script. */

interface FrameworkStatusResponse {
  counts: Record<string, number>;
  ecosystemDrift?: { registered: number; inDb: number; unknown: string[] };
}

function FrameworkStatus() {
  const { data } = useQuery({
    queryKey: ['framework-counts'],
    queryFn: () => apiFetch<FrameworkStatusResponse>('/frameworks/status'),
    // Low-priority status page — 4h (was 60s) to avoid keeping Neon awake.
    refetchInterval: 4 * 60 * 60 * 1000,
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
