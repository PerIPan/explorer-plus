'use client';
import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { decodeCvssVector, cvssSeverityFromScore } from '../../lib/cvss';
import { Badge } from './Badge';

interface Props {
  score: number | null;
  vector: string | null;
  /** Optional prefix label, e.g. 'CVSS v3.1'. Defaults to 'CVSS'. */
  label?: string;
}

/**
 * Clickable CVSS badge with a popover that decodes the vector string into
 * per-metric plain-English explanations. Uses a portal to document.body so
 * the popover isn't clipped by DataTable / overflow-hidden ancestors.
 *
 * Supports CVSS v3.0 / v3.1 only. v4 vectors render the badge with its
 * score/severity (if known) and show the raw vector in the popover with a
 * "v4 decoding not yet supported" notice.
 */
export function CvssBadge({ score, vector, label = 'CVSS' }: Props) {
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const decoded = decodeCvssVector(vector);
  const sev = cvssSeverityFromScore(score);

  useLayoutEffect(() => {
    if (!open || !btnRef.current) return;
    const r = btnRef.current.getBoundingClientRect();
    setPos({ top: r.bottom + window.scrollY + 4, left: r.left + window.scrollX });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (btnRef.current && !btnRef.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (score == null && !vector) return null;

  return (
    <>
      <button
        ref={btnRef}
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="dialog"
        className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border bg-[var(--surface-card)] border-[var(--border-color)] hover:border-[var(--accent-teal)] transition-colors cursor-pointer"
        title={vector ?? 'Click for breakdown'}
      >
        <span className="text-[var(--text-secondary)]">{label}</span>
        {score != null && <span className="font-mono text-[var(--text-primary)]">{score.toFixed(1)}</span>}
        <Badge label={sev.label} variant={sev.variant} />
      </button>
      {open && pos && typeof document !== 'undefined' && createPortal(
        <div
          role="dialog"
          aria-label="CVSS metric breakdown"
          style={{ top: pos.top, left: pos.left, position: 'absolute' }}
          className="z-[100] w-[420px] max-w-[90vw] bg-[var(--surface-card)] border border-[var(--border-color)] rounded-md shadow-xl p-3"
        >
          {decoded ? (
            <>
              <div className="text-[10px] uppercase tracking-wider text-[var(--text-secondary)] mb-2">
                CVSS v{decoded.version} · <span className="font-mono">{decoded.raw}</span>
              </div>
              <dl className="space-y-1.5 text-xs">
                {decoded.metrics.map((m) => (
                  <div key={m.key} className="grid grid-cols-[110px_60px_1fr] gap-2 items-baseline">
                    <dt className="text-[var(--text-secondary)]">{m.label}</dt>
                    <dd className="font-mono text-[var(--text-primary)]">{m.value}</dd>
                    <dd className="text-[var(--text-secondary)] text-[11px] leading-snug">{m.plainEnglish}</dd>
                  </div>
                ))}
              </dl>
            </>
          ) : (
            <div className="text-xs text-[var(--text-secondary)] space-y-1">
              <div>
                {vector?.startsWith('CVSS:4')
                  ? 'CVSS v4.0 decoding not yet supported.'
                  : 'CVSS vector not recognised.'}
              </div>
              {vector && <div className="font-mono text-[11px] break-all">{vector}</div>}
            </div>
          )}
        </div>,
        document.body,
      )}
    </>
  );
}
