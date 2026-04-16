'use client';
import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useFeedStatus } from '../hooks/useApi';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import type { FeedSyncStatus } from '../lib/types';

const SOURCE_LABELS: Record<string, string> = {
  otx: 'AlienVault OTX',
  abuse_ch: 'abuse.ch (ThreatFox + MalwareBazaar)',
  cisa_kev: 'CISA Known Exploited Vulnerabilities',
  rss: 'RSS Feeds (DFIR, Unit42, Microsoft, Talos)',
  d3fend: 'D3FEND Defensive Mappings',
  nvd: 'NVD CVE Enrichment',
  virustotal: 'VirusTotal Hash Enrichment',
  matview_refresh: 'Matview refresh (app_technique_groups + package_summary)',
  cve_products: 'CVE → Application enrichment (re-fetches NVD CPE data for CVEs missing products)',
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

function FeedCard({ feed }: FeedCardProps) {
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3">
      {/* Header row */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusDot status={feed.status} />
          <h3 className="text-[var(--text-primary)] font-medium text-sm">
            {SOURCE_LABELS[feed.source] ?? feed.source}
          </h3>
        </div>
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
        <span>Last sync: <span className="text-[var(--text-primary)]">{formatTimeAgo(feed.lastSync)}</span></span>
        <StatusBadge status={feed.status} />
      </div>

      {/* Error message */}
      {feed.error && (
        <div className="text-xs text-[var(--accent-orange)] bg-[var(--orange-faint)] border border-[var(--orange-dim)] rounded p-2 font-mono break-words">
          {feed.error}
        </div>
      )}
    </div>
  );
}

const AUTO_ONLY_SOURCES = new Set(['nvd', 'virustotal']);

/** Placeholder card for sources not yet in the DB log */
function EmptyFeedCard({ source }: { source: string }) {
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-[var(--text-secondary)]" />
          <h3 className="text-[var(--text-primary)] font-medium text-sm">
            {SOURCE_LABELS[source] ?? source}
          </h3>
        </div>
      </div>
      <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
        <span>Last sync: <span className="text-[var(--text-primary)]">—</span></span>
        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]">
          {AUTO_ONLY_SOURCES.has(source) ? 'scheduled' : 'pending'}
        </span>
      </div>
    </div>
  );
}

const ALL_SOURCES = ['otx', 'abuse_ch', 'cisa_kev', 'rss', 'nvd', 'virustotal'];

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

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {ALL_SOURCES.map((source) => {
          const feed = feedMap.get(source);

          if (!feed) {
            return (
              <EmptyFeedCard
                key={source}
                source={source}
              />
            );
          }

          return (
            <FeedCard
              key={source}
              feed={feed}
            />
          );
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
  /** If true, empty state is intentional — source data pending, not a sync failure */
  expectedEmpty?: boolean;
}

const FRAMEWORK_TABLES: FrameworkTable[] = [
  { key: 'owasp_top10', label: 'OWASP Top 10 (Web, ML, LLM)' },
  { key: 'csf_subcategories', label: 'NIST CSF v2 (Subcategories)' },
  { key: 'csf_technique_mappings', label: 'NIST CSF v2 (CRI Profile Mappings)' },
  { key: 'csf_implementation_examples', label: 'NIST CSF v2 (Implementation Examples)' },
  { key: 'csf_informative_references', label: 'NIST CSF v2 (Informative References — 800-53 + ISO 27001)' },
  { key: 'ghsa_advisories', label: 'GitHub Security Advisories' },
  { key: 'ghsa_weaknesses', label: 'GHSA CWE Mappings' },
  { key: 'ghsa_packages', label: 'GHSA Affected Packages' },
  { key: 'packages', label: 'Packages (derived from GHSA)' },
  { key: 'nist_controls', label: 'NIST 800-53' },
  { key: 'engage_mappings', label: 'MITRE Engage' },
  { key: 'defensive_mappings', label: 'D3FEND' },
  { key: 'detection_strategies', label: 'Detection Strategies' },
  { key: 'detection_analytics', label: 'Detection Analytics' },
  { key: 'react_actions', label: 'RE&CT' },
  { key: 'veris_mappings', label: 'VERIS' },
  { key: 'cloud_control_mappings', label: 'Cloud Controls (Azure + GCP)' },
  { key: 'sigma_rules', label: 'Sigma Rules' },
  { key: 'atomic_tests', label: 'Atomic Red Team' },
  { key: 'external_actors', label: 'ETDA Actors' },
  { key: 'applications', label: 'Applications (CVElistV5)' },
  { key: 'capec_mappings', label: 'CAPEC Bridge' },
  { key: 'ctid_mappings', label: 'CTID CVE→Technique' },
  { key: 'atlas_xrefs', label: 'ATLAS Cross-References' },
  { key: 'cve_details', label: 'CVE Details' },
  { key: 'cve_weaknesses', label: 'CVE Weaknesses' },
  { key: 'affected_products', label: 'Affected Products' },
];

function FrameworkStatus() {
  const { data } = useQuery({
    queryKey: ['framework-counts'],
    queryFn: () => apiFetch<{ counts: Record<string, number> }>('/frameworks/status'),
    refetchInterval: 60_000,
  });

  return (
    <div className="space-y-3 mt-8">
      <h2 className="text-sm font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
        Frameworks &amp; Static Data
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {FRAMEWORK_TABLES.map((fw) => {
          const count = data?.counts?.[fw.key];
          const hasData = count != null && count > 0;
          const isPending = !hasData && fw.expectedEmpty;
          const dotClass = hasData
            ? 'bg-[var(--accent-green)]'
            : isPending
              ? 'bg-[var(--accent-yellow)]'
              : 'bg-[var(--text-secondary)]';
          return (
            <div key={fw.key} className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span className={`inline-block w-2.5 h-2.5 rounded-full ${dotClass}`} />
                  <h3 className="text-[var(--text-primary)] font-medium text-sm">{fw.label}</h3>
                </div>
                {hasData && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]">
                    success
                  </span>
                )}
                {isPending && (
                  <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]">
                    pending source
                  </span>
                )}
              </div>
              <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
                <span>Last sync: <span className="text-[var(--text-primary)]">{hasData ? 'synced' : isPending ? 'awaiting source' : 'pending'}</span></span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
