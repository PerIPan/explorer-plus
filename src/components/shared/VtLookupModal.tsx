import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiFetch } from '../../lib/api';
import { Badge } from './Badge';

// ── Types ──────────────────────────────────────────────────────────────────────

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

// ── Verdict Ring ───────────────────────────────────────────────────────────────

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

// ── Modal ──────────────────────────────────────────────────────────────────────

export function VtLookupModal({ hash, onClose }: { hash: string; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['vt-lookup', hash],
    queryFn: () => apiFetch<VtData>(`/feed/vt-lookup`, { hash }),
    staleTime: 10 * 60 * 1000,
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
            <VtIcon />
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
                        <span className="font-mono text-[11px] text-[var(--accent-teal)] font-medium shrink-0">T{t.id}</span>
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

// ── VT Button (globe icon) ─────────────────────────────────────────────────────

export function VtButton({ hash, onClick }: { hash: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      title="Lookup on VirusTotal"
      className="flex-shrink-0 p-0.5 rounded text-[var(--accent-blue)] hover:bg-[var(--blue-faint)] transition-colors"
      aria-label="VirusTotal lookup"
    >
      <VtIcon />
    </button>
  );
}

function VtIcon() {
  return (
    <div className="w-5 h-5 rounded bg-[var(--blue-faint)] border border-[var(--blue-dim)] flex items-center justify-center">
      <svg className="w-3 h-3 text-[var(--accent-blue)]" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z" />
      </svg>
    </div>
  );
}
