import { useState } from 'react';
import { useDataSource } from '../../hooks/useApi';
import { EntityLink } from '../shared/EntityLink';
import { Badge } from '../shared/Badge';
import { sanitize, sanitizeMarkdown } from '../../lib/sanitize';

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
          <span className="text-[var(--accent-pink)] w-4 h-4 shrink-0">{icon}</span>
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

/** Labeled row with a fixed-width prefix and flexible children area */
function MapRow({ prefix, children }: { prefix: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs text-[var(--text-secondary)] w-32 shrink-0 pt-0.5">{prefix}</span>
      <div className="flex-1 flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

// ── Icons ──────────────────────────────────────────────────────────────────────

const IconLayers = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
  </svg>
);

const IconEye = (
  <svg fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" className="w-4 h-4">
    <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
  </svg>
);

// ── Types for API-extended shape ───────────────────────────────────────────────

interface DataSourceTechniqueEntry {
  attackId: string;
  name: string;
  componentName: string;
}

interface DataSourceWithTechniques {
  techniques?: DataSourceTechniqueEntry[];
}

// ── Main component ─────────────────────────────────────────────────────────────

interface DataSourceMapViewProps {
  attackId: string;
}

/**
 * Structured overview of a data source entity and its detection coverage.
 * Shows data components and the techniques they help detect.
 */
export function DataSourceMapView({ attackId }: DataSourceMapViewProps) {
  const { data: dataSource, isLoading, error } = useDataSource(attackId);

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-[var(--text-secondary)] text-sm py-8 justify-center">
        <span className="inline-block w-5 h-5 border-2 border-[var(--pink-dim)] border-t-[var(--accent-pink)] rounded-full animate-spin" />
        Loading data source map...
      </div>
    );
  }

  if (error || !dataSource) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        Failed to load data source data.
      </div>
    );
  }

  // The API returns `techniques` on the detail endpoint even though the TS type
  // does not declare it. Access via a cast to the extended shape.
  const extended = dataSource as typeof dataSource & DataSourceWithTechniques;
  const techniques: DataSourceTechniqueEntry[] = extended.techniques ?? [];
  const components = dataSource.components ?? [];

  // Group techniques by component name for the Detectable Techniques section
  const techniquesByComponent = techniques.reduce<Record<string, DataSourceTechniqueEntry[]>>(
    (acc, t) => {
      const key = t.componentName ?? 'Unknown';
      if (!acc[key]) acc[key] = [];
      acc[key].push(t);
      return acc;
    },
    {}
  );

  const uniqueTechniqueCount = new Set(techniques.map((t) => t.attackId)).size;

  return (
    <div className="space-y-3">

      {/* Header */}
      <div className="pb-1">
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">{dataSource.name}</h2>
        <div className="flex flex-wrap items-center gap-2 mt-1">
          <span className="font-mono text-xs text-[var(--accent-pink)] bg-[var(--pink-faint)] border border-[var(--pink-dim)] px-2 py-0.5 rounded">
            {dataSource.attackId}
          </span>
          <Badge label="data source" variant="pink" />
          {dataSource.isDeprecated && <Badge label="deprecated" variant="neutral" />}
          {dataSource.isRevoked && <Badge label="revoked" variant="neutral" />}
          {(dataSource.platforms ?? []).map((p) => (
            <Badge key={p} label={p} variant="blue" />
          ))}
        </div>
      </div>

      {/* Description */}
      {dataSource.description && (
        <div className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-lg p-4">
          <p
            className="text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap"
            dangerouslySetInnerHTML={{
              __html: sanitize(sanitizeMarkdown(dataSource.description)),
            }}
          />
        </div>
      )}

      {/* Data Components */}
      <MapCard label="Data Components" icon={IconLayers} count={components.length} defaultOpen>
        {components.length > 0 ? (
          <div className="space-y-4">
            {components.map((component) => (
              <div key={component.id} className="space-y-1">
                <p className="text-xs font-semibold text-[var(--text-primary)] uppercase tracking-wide">
                  {component.name}
                </p>
                {component.description && (
                  <p
                    className="text-xs text-[var(--text-secondary)] leading-relaxed"
                    dangerouslySetInnerHTML={{ __html: sanitize(sanitizeMarkdown(component.description)) }}
                  />
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No data components defined.</p>
        )}
      </MapCard>

      {/* Detectable Techniques */}
      <MapCard label="Detectable Techniques" icon={IconEye} count={uniqueTechniqueCount} defaultOpen>
        {techniques.length > 0 ? (
          <div className="space-y-4">
            {Object.entries(techniquesByComponent).map(([componentName, techs]) => (
              <div key={componentName} className="space-y-2">
                {/* Component group header */}
                <div className="flex items-center gap-2">
                  <Badge label={componentName} variant="pink" />
                  <span className="text-[10px] text-[var(--text-secondary)]">
                    {techs.length} technique{techs.length !== 1 ? 's' : ''}
                  </span>
                </div>
                {/* Technique links */}
                <div className="flex flex-wrap gap-1.5 pl-1">
                  {techs.map((t) => (
                    <EntityLink
                      key={t.attackId}
                      type="technique"
                      attackId={t.attackId}
                      name={t.name}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-[var(--text-secondary)]">No techniques linked to this data source.</p>
        )}
      </MapCard>

      {/* Reference */}
      {dataSource.url && (
        <div className="pt-1">
          <MapRow prefix="Reference">
            <a
              href={dataSource.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-[var(--accent-pink)] hover:underline hover:opacity-80 transition-opacity"
            >
              MITRE ATT&CK — {dataSource.name}
            </a>
          </MapRow>
        </div>
      )}

    </div>
  );
}
