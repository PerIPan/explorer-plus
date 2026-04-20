'use client';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { useCapecPattern } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import { EntityLink } from '../components/shared/EntityLink';
import { FrameworkMapCard } from '../components/relationships/shared/FrameworkMapCard';
import { DiamondLoader } from '../components/shared/FoldingDiamond';
import { CAPEC_SEVERITY_VARIANTS, CAPEC_LIKELIHOOD_VARIANTS } from '../lib/capecVariants';

const NATURE_LABELS: Record<string, string> = {
  ChildOf: 'Parent pattern',
  ParentOf: 'Child patterns',
  CanPrecede: 'Can precede',
  CanFollow: 'Can follow',
};

export function CapecDetail() {
  const { id: rawId } = useParams<{ id: string }>();
  const capecId = (rawId ?? '').toUpperCase();
  const { data, isLoading, error } = useCapecPattern(capecId);

  if (isLoading) return <DiamondLoader text="Loading CAPEC pattern..." />;
  if (error || !data) {
    return (
      <div className="text-[var(--accent-orange)] text-sm py-8 text-center">
        CAPEC pattern not found.
      </div>
    );
  }

  const relatedGrouped = new Map<string, Array<{ capecId: string; name: string | null }>>();
  for (const r of data.related ?? []) {
    const arr = relatedGrouped.get(r.nature) ?? [];
    arr.push({ capecId: r.relatedCapecId, name: r.name });
    relatedGrouped.set(r.nature, arr);
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title={`${data.capecId}: ${data.name}`}
        subtitle={data.description?.slice(0, 200) ?? 'CAPEC Attack Pattern'}
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            {data.abstraction && <Badge label={data.abstraction} variant="neutral" />}
            {data.severity && (
              <Badge label={`Severity: ${data.severity}`} variant={CAPEC_SEVERITY_VARIANTS[data.severity] ?? 'neutral'} />
            )}
            {data.likelihood && (
              <Badge label={`Likelihood: ${data.likelihood}`} variant={CAPEC_LIKELIHOOD_VARIANTS[data.likelihood] ?? 'neutral'} />
            )}
            {data.status && <Badge label={data.status} variant="neutral" />}
            <a
              href={`https://capec.mitre.org/data/definitions/${data.capecId.replace('CAPEC-', '')}.html`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-[var(--accent-teal)] hover:underline"
            >
              View on capec.mitre.org ↗
            </a>
          </div>
        }
      />

      {data.description && (
        <FrameworkMapCard label="Description" labelColor="#fbbf24" defaultOpen>
          <p className="text-sm text-[var(--text-secondary)] whitespace-pre-wrap leading-relaxed">
            {data.description}
          </p>
        </FrameworkMapCard>
      )}

      {data.cweIds && data.cweIds.length > 0 && (
        <FrameworkMapCard label="Weakness References (CWE)" labelColor="#3b82f6" count={data.cweIds.length} defaultOpen>
          <div className="flex flex-wrap gap-1.5">
            {data.cweIds.map((cwe) => (
              <a
                key={cwe}
                href={`https://cwe.mitre.org/data/definitions/${cwe.replace('CWE-', '')}.html`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono border bg-[var(--blue-faint)] text-[var(--accent-blue)] border-[var(--blue-dim)] hover:underline"
              >
                {cwe}
              </a>
            ))}
          </div>
        </FrameworkMapCard>
      )}

      {data.techniques.length > 0 && (
        <FrameworkMapCard
          label="Linked ATT&CK Techniques"
          labelColor="#14b8a6"
          count={data.techniques.length}
          defaultOpen
        >
          <div className="flex flex-wrap gap-1.5">
            {data.techniques.map((t) => (
              <EntityLink key={t.attackId} type="technique" attackId={t.attackId} name={t.name} useMap />
            ))}
          </div>
        </FrameworkMapCard>
      )}

      {data.prerequisites && data.prerequisites.length > 0 && (
        <FrameworkMapCard label="Prerequisites" labelColor="#fbbf24" count={data.prerequisites.length}>
          <ul className="space-y-1.5 pl-4 list-disc marker:text-[var(--accent-yellow)]">
            {data.prerequisites.map((p, i) => (
              <li key={i} className="text-xs text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                {p}
              </li>
            ))}
          </ul>
        </FrameworkMapCard>
      )}

      {data.skillsRequired && Object.keys(data.skillsRequired).length > 0 && (
        <FrameworkMapCard label="Skills Required" labelColor="#fbbf24" count={Object.keys(data.skillsRequired).length}>
          <div className="space-y-2">
            {Object.entries(data.skillsRequired).map(([level, desc]) => (
              <div key={level} className="text-xs">
                <div className="mb-1">
                  <Badge label={level} variant={CAPEC_LIKELIHOOD_VARIANTS[level] ?? 'neutral'} />
                </div>
                <p className="text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap pl-2">{desc}</p>
              </div>
            ))}
          </div>
        </FrameworkMapCard>
      )}

      {data.consequences && Object.keys(data.consequences).length > 0 && (
        <FrameworkMapCard
          label="Consequences"
          labelColor="#f472b6"
          count={Object.keys(data.consequences).length}
        >
          <div className="space-y-1.5">
            {Object.entries(data.consequences).map(([category, impacts]) => (
              <div key={category} className="flex items-baseline gap-3 text-xs">
                <span className="text-[var(--text-secondary)] min-w-[140px]">{category.replace(/_/g, ' ')}</span>
                <div className="flex flex-wrap gap-1">
                  {impacts.map((impact, i) => (
                    <Badge key={i} label={impact} variant="pink" />
                  ))}
                </div>
              </div>
            ))}
          </div>
        </FrameworkMapCard>
      )}

      {data.mitigations.length > 0 && (
        <FrameworkMapCard
          label="Mitigations"
          labelColor="#14b8a6"
          count={data.mitigations.length}
        >
          <ul className="space-y-2">
            {data.mitigations.map((m, i) => (
              <li key={i} className="text-xs text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                {m.description ?? m.name}
              </li>
            ))}
          </ul>
        </FrameworkMapCard>
      )}

      {data.exampleInstances && data.exampleInstances.length > 0 && (
        <FrameworkMapCard
          label="Example Instances"
          labelColor="#a78bfa"
          count={data.exampleInstances.length}
        >
          <ul className="space-y-2">
            {data.exampleInstances.map((ex, i) => (
              <li key={i} className="text-xs text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap">
                {ex}
              </li>
            ))}
          </ul>
        </FrameworkMapCard>
      )}

      {data.resourcesRequired && data.resourcesRequired.length > 0 && (
        <FrameworkMapCard label="Resources Required" labelColor="#fbbf24" count={data.resourcesRequired.length}>
          <ul className="space-y-1.5 pl-4 list-disc marker:text-[var(--accent-yellow)]">
            {data.resourcesRequired.map((r, i) => (
              <li key={i} className="text-xs text-[var(--text-secondary)] leading-relaxed">
                {r}
              </li>
            ))}
          </ul>
        </FrameworkMapCard>
      )}

      {relatedGrouped.size > 0 && (
        <FrameworkMapCard label="Related Patterns" labelColor="#fbbf24" count={data.related.length}>
          <div className="space-y-3">
            {Array.from(relatedGrouped.entries()).map(([nature, items]) => (
              <div key={nature}>
                <div className="text-[10px] font-semibold text-[var(--text-secondary)] uppercase tracking-wider mb-1">
                  {NATURE_LABELS[nature] ?? nature} ({items.length})
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {items.map((r) => (
                    <Link
                      key={r.capecId}
                      href={`/cti/capec/${r.capecId}`}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] border bg-[var(--yellow-faint)] text-[var(--accent-yellow)] border-[var(--yellow-dim)] hover:underline"
                    >
                      <span className="font-mono">{r.capecId}</span>
                      {r.name && <span>— {r.name}</span>}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </FrameworkMapCard>
      )}
    </div>
  );
}
