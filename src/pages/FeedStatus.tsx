import { useState, useEffect } from 'react';
import { useFeedStatus } from '../hooks/useApi';
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

interface SyncButtonProps {
  source: string;
  disabled: boolean;
  onSync: (source: string) => void;
}

function SyncButton({ source, disabled, onSync }: SyncButtonProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={() => onSync(source)}
      className="px-3 py-1 text-xs rounded-md border border-[var(--teal-dim)] text-[var(--accent-teal)] bg-[var(--teal-ghost)] hover:bg-[var(--teal-faint)] disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
    >
      {disabled ? 'Syncing...' : 'Sync Now'}
    </button>
  );
}

interface FeedCardProps {
  feed: FeedSyncStatus;
  syncing: boolean;
  onSync: (source: string) => void;
}

function FeedCard({ feed, syncing, onSync }: FeedCardProps) {
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
        {!AUTO_ONLY_SOURCES.has(feed.source) && (
          <SyncButton source={feed.source} disabled={syncing} onSync={onSync} />
        )}
      </div>

      {/* Stats row */}
      <div className="flex items-center gap-4 text-xs text-[var(--text-secondary)]">
        <span>Last sync: <span className="text-[var(--text-primary)]">{formatTimeAgo(feed.lastSync)}</span></span>
        <span>Inserted: <span className="text-[var(--accent-teal)]">{feed.recordsInserted.toLocaleString()}</span></span>
        <span>Skipped: <span className="text-[var(--text-primary)]">{feed.recordsSkipped.toLocaleString()}</span></span>
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
function EmptyFeedCard({ source, syncing, onSync }: { source: string; syncing: boolean; onSync: (s: string) => void }) {
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="inline-block w-2.5 h-2.5 rounded-full bg-[var(--text-secondary)]" />
          <h3 className="text-[var(--text-primary)] font-medium text-sm">
            {SOURCE_LABELS[source] ?? source}
          </h3>
        </div>
        {!AUTO_ONLY_SOURCES.has(source) && (
          <SyncButton source={source} disabled={syncing} onSync={onSync} />
        )}
      </div>
      <p className="text-xs text-[var(--text-secondary)]">
        {AUTO_ONLY_SOURCES.has(source) ? 'Runs automatically via cron' : 'Never synced'}
      </p>
    </div>
  );
}

const ALL_SOURCES = ['otx', 'abuse_ch', 'cisa_kev', 'rss', 'd3fend', 'nvd', 'virustotal'];

export function FeedStatus() {
  const { data, refetch } = useFeedStatus();
  const [syncingSet, setSyncingSet] = useState<Set<string>>(new Set());
  const [syncErrors, setSyncErrors] = useState<Record<string, string>>({});

  const feedMap = new Map<string, FeedSyncStatus>(
    (data?.data ?? []).map((f) => [f.source, f]),
  );

  /** Poll every 5s while any source is in running state (FIX 35) */
  const hasRunning = (data?.data ?? []).some((f) => f.status === 'running');
  useEffect(() => {
    if (!hasRunning) return;
    const interval = setInterval(() => { void refetch(); }, 5000);
    return () => clearInterval(interval);
  }, [hasRunning, refetch]);

  async function handleSync(source: string) {
    setSyncingSet((prev) => new Set([...prev, source]));
    setSyncErrors((prev) => {
      const next = { ...prev };
      delete next[source];
      return next;
    });

    try {
      const resp = await fetch(`/api/v1/feed/${source}/sync`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      if (!resp.ok) {
        const body = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
        setSyncErrors((prev) => ({
          ...prev,
          [source]: (body as { error?: string }).error ?? `HTTP ${resp.status}`,
        }));
      }
    } catch (err) {
      setSyncErrors((prev) => ({
        ...prev,
        [source]: err instanceof Error ? err.message : 'Network error',
      }));
    } finally {
      setSyncingSet((prev) => {
        const next = new Set(prev);
        next.delete(source);
        return next;
      });
      void refetch();
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Feed Status"
        subtitle="CTI ingestion pipeline health and manual sync controls"
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {ALL_SOURCES.map((source) => {
          const feed = feedMap.get(source);
          const syncing = syncingSet.has(source);

          if (!feed) {
            return (
              <EmptyFeedCard
                key={source}
                source={source}
                syncing={syncing}
                onSync={handleSync}
              />
            );
          }

          const feedWithError: FeedSyncStatus = syncErrors[source]
            ? { ...feed, error: syncErrors[source], status: 'error' }
            : feed;

          return (
            <FeedCard
              key={source}
              feed={feedWithError}
              syncing={syncing}
              onSync={handleSync}
            />
          );
        })}
      </div>
    </div>
  );
}
