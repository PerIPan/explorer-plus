import { useCallback, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { useIocs } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { apiFetch } from '../lib/api';
import { PageHeader } from '../components/layout/PageHeader';
import { DataTable, type ColumnDef } from '../components/shared/DataTable';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';
import type { IocEntry } from '../lib/types';

/** Clipboard copy button with brief "Copied!" feedback */
function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }).catch(() => {/* silent fail */});
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      title="Copy to clipboard"
      className={`ml-1.5 flex-shrink-0 transition-colors duration-150 ${copied ? 'text-[var(--accent-teal)]' : 'text-[var(--text-secondary)] hover:text-[var(--accent-teal)]'}`}
      aria-label="Copy value"
    >
      {copied ? (
        <span className="text-[10px] font-medium">Copied!</span>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-4 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
        </svg>
      )}
    </button>
  );
}

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email'];
const SOURCES = ['otx', 'threatfox', 'malwarebazaar', 'cisa_kev'];

const TYPE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  ip: 'orange',
  domain: 'teal',
  url: 'blue',
  hash: 'purple',
  email: 'green',
};

const SOURCE_VARIANTS: Record<string, 'teal' | 'orange' | 'purple' | 'blue' | 'green' | 'pink'> = {
  otx: 'teal',
  threatfox: 'orange',
  malwarebazaar: 'purple',
  cisa_kev: 'blue',
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/** Generate OTX indicator URL from IOC type and value */
function otxUrl(type: string, value: string): string | null {
  const map: Record<string, string> = {
    cve: 'cve', ip: 'IPv4', domain: 'domain', url: 'url', hash: 'file', email: 'email',
  };
  const otxType = map[type];
  return otxType ? `https://otx.alienvault.com/indicator/${otxType}/${encodeURIComponent(value)}` : null;
}

/** Clickable technique count with popover showing linked techniques */
function TechniquePopover({ iocId, count }: { iocId: string; count: number }) {
  const [open, setOpen] = useState(false);
  const { data, isLoading } = useQuery({
    queryKey: ['ioc-techniques', iocId],
    queryFn: () => apiFetch<{ data: Array<{ attackId: string; name: string }> }>(`/feed/iocs/${iocId}/techniques`),
    enabled: open,
  });

  return (
    <div className="relative">
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen(!open); }}
        className="cursor-pointer"
      >
        <Badge label={String(count)} variant="teal" />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 top-8 z-50 bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg shadow-2xl p-3 min-w-[240px] max-h-[300px] overflow-y-auto">
            <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-2">
              Linked Techniques ({count})
            </div>
            {isLoading && (
              <div className="flex items-center gap-2 text-[var(--text-secondary)] text-xs py-2">
                <span className="inline-block w-3 h-3 border-2 border-[var(--teal-dim)] border-t-[var(--accent-teal)] rounded-full animate-spin" />
                Loading...
              </div>
            )}
            {data?.data && (
              <div className="flex flex-col gap-1">
                {data.data.map((t) => (
                  <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} />
                ))}
              </div>
            )}
            {!isLoading && data?.data?.length === 0 && (
              <span className="text-xs text-[var(--text-secondary)]">No techniques found.</span>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ── VirusTotal Lookup Modal ────────────────────────────────────────────────────

interface VtData {
  hash: string;
  fileName: string | null;
  fileType: string | null;
  fileSize: number | null;
  tags: string[];
  stats: { malicious: number; suspicious: number; harmless: number; undetected: number; total: number };
  sigmaStats: { critical: number; high: number; medium: number; low: number } | null;
  techniques: Array<{ id: string; severity: string; description: string }>;
  sigmaRules: Array<{ title: string; level: string }>;
  network: { dnsLookups: number; ipTraffic: number };
}

const SEVERITY_LABELS: Record<string, string> = {
  IMPACT_SEVERITY_HIGH: 'HIGH',
  IMPACT_SEVERITY_MEDIUM: 'MED',
  IMPACT_SEVERITY_LOW: 'LOW',
  IMPACT_SEVERITY_INFO: 'INFO',
};

const SEVERITY_CLASSES: Record<string, string> = {
  IMPACT_SEVERITY_HIGH: 'bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]',
  IMPACT_SEVERITY_MEDIUM: 'bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]',
  IMPACT_SEVERITY_LOW: 'bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)]',
  IMPACT_SEVERITY_INFO: 'bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]',
};

function VtVerdictRing({ malicious, total }: { malicious: number; total: number }) {
  const pct = total > 0 ? malicious / total : 0;
  const r = 36;
  const circ = 2 * Math.PI * r;
  const offset = circ * (1 - pct);
  const color = pct > 0.5 ? 'var(--accent-pink)' : pct > 0.2 ? 'var(--accent-orange)' : pct > 0 ? 'var(--accent-yellow)' : 'var(--accent-green)';

  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="88" height="88" viewBox="0 0 88 88">
        <circle cx="44" cy="44" r={r} fill="none" stroke="var(--border-color)" strokeWidth="6" opacity="0.3" />
        <circle
          cx="44" cy="44" r={r}
          fill="none" stroke={color} strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          transform="rotate(-90 44 44)"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text x="44" y="40" textAnchor="middle" fill={color} fontSize="18" fontWeight="700">{malicious}</text>
        <text x="44" y="56" textAnchor="middle" fill="var(--text-secondary)" fontSize="10">/{total}</text>
      </svg>
      <span className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)]">Detections</span>
    </div>
  );
}

function VtLookupModal({ hash, onClose }: { hash: string; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['vt-lookup', hash],
    queryFn: () => apiFetch<VtData>(`/feed/vt-lookup`, { hash }),
    staleTime: 10 * 60 * 1000, // cache 10 min
  });

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-xl shadow-2xl w-[95vw] max-w-[640px] max-h-[85vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--border-color)]">
          <div className="flex items-center gap-2.5">
            <div className="w-6 h-6 rounded bg-[var(--blue-faint)] border border-[var(--blue-dim)] flex items-center justify-center">
              <svg className="w-3.5 h-3.5 text-[var(--accent-blue)]" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
              </svg>
            </div>
            <div>
              <span className="text-sm font-semibold text-[var(--text-primary)]">VirusTotal</span>
              <span className="text-[10px] text-[var(--text-secondary)] ml-2 font-mono">{hash.slice(0, 16)}...</span>
            </div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="px-5 py-4">
          {isLoading && (
            <div className="flex flex-col items-center gap-3 py-12">
              <span className="inline-block w-6 h-6 border-2 border-[var(--blue-dim)] border-t-[var(--accent-blue)] rounded-full animate-spin" />
              <span className="text-sm text-[var(--text-secondary)]">Querying VirusTotal...</span>
            </div>
          )}

          {error && (
            <div className="text-center py-8">
              <p className="text-sm text-[var(--accent-orange)]">
                {(error as Error).message?.includes('404') ? 'Hash not found in VirusTotal' : 'VirusTotal lookup failed'}
              </p>
              <p className="text-xs text-[var(--text-secondary)] mt-1">This hash may not have been submitted to VT yet.</p>
            </div>
          )}

          {data && (
            <div className="space-y-5">
              {/* Top row: verdict ring + file info */}
              <div className="flex gap-5 items-start">
                <VtVerdictRing malicious={data.stats.malicious} total={data.stats.total} />
                <div className="flex-1 min-w-0 space-y-2">
                  {data.fileName && (
                    <div>
                      <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">File Name</div>
                      <div className="text-sm text-[var(--text-primary)] font-medium truncate">{data.fileName}</div>
                    </div>
                  )}
                  <div className="flex gap-4">
                    {data.fileType && (
                      <div>
                        <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">Type</div>
                        <div className="text-xs text-[var(--text-primary)]">{data.fileType}</div>
                      </div>
                    )}
                    {data.fileSize && (
                      <div>
                        <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">Size</div>
                        <div className="text-xs text-[var(--text-primary)]">{(data.fileSize / 1024).toFixed(1)} KB</div>
                      </div>
                    )}
                  </div>
                  {/* Stats row */}
                  <div className="flex gap-2 flex-wrap">
                    <span className="text-[10px] px-2 py-0.5 rounded-full border bg-[var(--pink-faint)] text-[var(--accent-pink)] border-[var(--pink-dim)]">
                      {data.stats.malicious} malicious
                    </span>
                    {data.stats.suspicious > 0 && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full border bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)]">
                        {data.stats.suspicious} suspicious
                      </span>
                    )}
                    <span className="text-[10px] px-2 py-0.5 rounded-full border bg-[var(--green-faint)] text-[var(--accent-green)] border-[var(--green-dim)]">
                      {data.stats.harmless} clean
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded-full border bg-[var(--hover-overlay)] text-[var(--text-secondary)] border-[var(--border-color)]">
                      {data.stats.undetected} undetected
                    </span>
                  </div>
                </div>
              </div>

              {/* Tags */}
              {data.tags.length > 0 && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-1.5">Tags</div>
                  <div className="flex flex-wrap gap-1.5">
                    {data.tags.map((tag) => (
                      <span key={tag} className="text-[10px] px-2 py-0.5 rounded bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-secondary)]">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* ATT&CK Techniques */}
              {data.techniques.length > 0 && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-1.5">
                    Sandbox ATT&CK Techniques ({data.techniques.length})
                  </div>
                  <div className="space-y-1 max-h-[200px] overflow-y-auto">
                    {data.techniques.map((t, i) => (
                      <div key={`${t.id}-${i}`} className="flex items-center gap-2 py-1 px-2 rounded bg-[var(--surface-card)] border border-[var(--border-color)]">
                        <span className="font-mono text-[11px] text-[var(--accent-teal)] font-medium shrink-0">
                          T{t.id}
                        </span>
                        <span className={`text-[9px] px-1.5 py-0.5 rounded-full border font-medium shrink-0 ${SEVERITY_CLASSES[t.severity] ?? SEVERITY_CLASSES.IMPACT_SEVERITY_INFO}`}>
                          {SEVERITY_LABELS[t.severity] ?? 'INFO'}
                        </span>
                        <span className="text-[11px] text-[var(--text-secondary)] truncate">{t.description}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Sigma Rules */}
              {data.sigmaRules.length > 0 && (
                <div>
                  <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider mb-1.5">
                    Sigma Matches ({data.sigmaRules.length})
                  </div>
                  <div className="space-y-1">
                    {data.sigmaRules.map((s, i) => (
                      <div key={i} className="flex items-center gap-2 py-1 px-2 rounded bg-[var(--surface-card)] border border-[var(--border-color)]">
                        <span className="text-[10px] px-1.5 py-0.5 rounded-full border bg-[var(--orange-faint)] text-[var(--accent-orange)] border-[var(--orange-dim)] shrink-0">
                          {s.level}
                        </span>
                        <span className="text-[11px] text-[var(--text-primary)] truncate">{s.title}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Network */}
              {(data.network.dnsLookups > 0 || data.network.ipTraffic > 0) && (
                <div className="flex gap-4">
                  <div>
                    <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">DNS Lookups</div>
                    <div className="text-sm text-[var(--text-primary)] font-medium">{data.network.dnsLookups}</div>
                  </div>
                  <div>
                    <div className="text-[10px] text-[var(--text-secondary)] uppercase tracking-wider">IP Connections</div>
                    <div className="text-sm text-[var(--text-primary)] font-medium">{data.network.ipTraffic}</div>
                  </div>
                </div>
              )}

              {/* Link to VT */}
              <div className="pt-2 border-t border-[var(--border-color)]">
                <a
                  href={`https://www.virustotal.com/gui/file/${hash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-[var(--accent-teal)] hover:underline"
                >
                  View full report on VirusTotal
                </a>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/** VT lookup button — only shown for hash IOCs */
function VtButton({ hash, onClick }: { hash: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      title="Lookup on VirusTotal"
      className="ml-1 flex-shrink-0 p-0.5 rounded text-[var(--accent-blue)] hover:bg-[var(--blue-faint)] transition-colors"
      aria-label="VirusTotal lookup"
    >
      <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
      </svg>
    </button>
  );
}

// ── Columns + Page ─────────────────────────────────────────────────────────────

export function IocsList() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { sectorParam } = useSector();
  const [vtHash, setVtHash] = useState<string | null>(null);

  const page = parseInt(searchParams.get('page') ?? '1', 10);
  const type = searchParams.get('type') ?? '';
  const source = searchParams.get('source') ?? '';
  const q = searchParams.get('q') ?? '';

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        if (key !== 'page') next.set('page', '1');
        return next;
      });
    },
    [setSearchParams],
  );

  const params: Record<string, string> = { page: String(page), limit: '100', ...sectorParam };
  if (type) params.type = type;
  if (source) params.source = source;
  if (q) params.q = q;

  const { data, isLoading } = useIocs(params);

  const columns: ColumnDef<IocEntry>[] = [
    {
      key: 'type',
      header: 'Type',
      width: '90px',
      render: (row) => (
        <Badge label={row.type} variant={TYPE_VARIANTS[row.type] ?? 'neutral'} />
      ),
    },
    {
      key: 'value',
      header: 'Value',
      render: (row) => {
        const link = otxUrl(row.type, row.value);
        const showDesc = row.type === 'cve' && row.description;
        const isHash = row.type === 'hash';
        return (
          <div className={showDesc ? 'flex flex-col gap-0.5' : ''}>
            <div className="flex items-center gap-0.5">
              {link ? (
                <a
                  href={link}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-mono text-xs text-[var(--accent-teal)] hover:underline max-w-[240px] truncate"
                  title={row.value}
                >
                  {row.value}
                </a>
              ) : (
                <span
                  className="font-mono text-xs text-[var(--text-primary)] max-w-[240px] truncate"
                  title={row.value}
                >
                  {row.value}
                </span>
              )}
              <CopyButton value={row.value} />
              {isHash && <VtButton hash={row.value} onClick={() => setVtHash(row.value)} />}
            </div>
            {showDesc && (
              <span
                className="text-[11px] text-[var(--text-secondary)] max-w-[320px] truncate"
                title={row.description!}
              >
                {row.description}
              </span>
            )}
          </div>
        );
      },
    },
    {
      key: 'source',
      header: 'Source',
      width: '140px',
      render: (row) => (
        <Badge label={row.source} variant={SOURCE_VARIANTS[row.source] ?? 'neutral'} />
      ),
    },
    {
      key: 'malware_family',
      header: 'Malware Family',
      width: '160px',
      render: (row) =>
        row.malware_family ? (
          <span className="text-[var(--accent-orange)] text-xs">{row.malware_family}</span>
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
    {
      key: 'first_seen_at',
      header: 'First Seen',
      width: '120px',
      render: (row) => (
        <span className="text-[var(--text-secondary)] text-xs">{formatDate(row.first_seen_at)}</span>
      ),
    },
    {
      key: 'technique_count',
      header: 'Techniques',
      width: '100px',
      align: 'center',
      render: (row) =>
        (row.technique_count ?? 0) > 0 ? (
          <TechniquePopover iocId={row.id} count={row.technique_count!} />
        ) : (
          <span className="text-[var(--text-secondary)] text-xs">—</span>
        ),
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Indicators of Compromise"
        subtitle="Hashes, domains, IPs, and URLs from ThreatFox, MalwareBazaar, and OTX"
      />

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <input
          type="search"
          placeholder="Search IOCs..."
          value={q}
          onChange={(e) => setParam('q', e.target.value)}
          className="min-w-[200px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] placeholder-[var(--text-secondary)] focus:outline-none focus:border-[var(--accent-teal)]"
        />
        <select
          value={type}
          onChange={(e) => setParam('type', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t.toUpperCase()}</option>
          ))}
        </select>
        <select
          value={source}
          onChange={(e) => setParam('source', e.target.value)}
          className="min-w-[140px] px-3 py-1.5 rounded-md text-sm bg-[var(--surface-card)] border border-[var(--border-color)] text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent-teal)]"
        >
          <option value="">All Sources</option>
          {SOURCES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      <DataTable
        columns={columns}
        data={data?.data ?? []}
        loading={isLoading}
        pagination={data?.pagination}
        onPageChange={(p) => setParam('page', String(p))}
        rowKey={(row) => row.id}
        emptyMessage="No IOCs found. Trigger a feed sync to populate data."
      />

      {/* VT Lookup Modal */}
      {vtHash && <VtLookupModal hash={vtHash} onClose={() => setVtHash(null)} />}
    </div>
  );
}
