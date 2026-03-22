import { useSearchParams } from 'react-router-dom';
import { useSearch } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { EntityLink } from '../components/shared/EntityLink';
import { Badge } from '../components/shared/Badge';

function SectionHeader({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-3 mb-3">
      <h2 className="text-sm font-semibold text-[#ccd6f6] uppercase tracking-wider">
        {label}
      </h2>
      <span className="text-xs font-semibold text-[#64ffda] bg-[#64ffda18] border border-[#64ffda33] px-2 py-0.5 rounded-full tabular-nums">
        {count}
      </span>
    </div>
  );
}

export function Search() {
  const [searchParams] = useSearchParams();
  const q = searchParams.get('q') ?? '';

  const { data, isLoading, error } = useSearch(q);

  const totalCount =
    (data?.techniques.length ?? 0) +
    (data?.groups.length ?? 0) +
    (data?.software.length ?? 0) +
    (data?.mitigations.length ?? 0) +
    (data?.campaigns.length ?? 0) +
    (data?.data_sources.length ?? 0);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Search Results"
        subtitle={
          q
            ? `Results for "${q}"`
            : 'Enter a search term in the top bar (at least 3 characters)'
        }
      />

      {/* Short query hint */}
      {q.length > 0 && q.trim().length < 3 && (
        <p className="text-[#8892b0] text-sm">
          Please enter at least 3 characters to search.
        </p>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center text-[#8892b0]">
          <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
          Searching...
        </div>
      )}

      {/* Error */}
      {error && (
        <p className="text-[#f97316] text-sm">Search failed. Try again.</p>
      )}

      {/* No results */}
      {!isLoading && !error && data && totalCount === 0 && (
        <p className="text-[#8892b0] text-sm">
          No results found for "{q}".
        </p>
      )}

      {data && totalCount > 0 && (
        <div className="space-y-8">
          {/* Summary bar */}
          <div className="flex flex-wrap gap-2 text-xs">
            {data.techniques.length > 0 && (
              <Badge label={`${data.techniques.length} Techniques`} variant="teal" />
            )}
            {data.groups.length > 0 && (
              <Badge label={`${data.groups.length} Groups`} variant="orange" />
            )}
            {data.software.length > 0 && (
              <Badge label={`${data.software.length} Software`} variant="purple" />
            )}
            {data.mitigations.length > 0 && (
              <Badge label={`${data.mitigations.length} Mitigations`} variant="green" />
            )}
            {data.campaigns.length > 0 && (
              <Badge label={`${data.campaigns.length} Campaigns`} variant="blue" />
            )}
            {data.data_sources.length > 0 && (
              <Badge label={`${data.data_sources.length} Data Sources`} variant="pink" />
            )}
          </div>

          {/* Techniques */}
          {data.techniques.length > 0 && (
            <section>
              <SectionHeader label="Techniques" count={data.techniques.length} />
              <div className="flex flex-wrap gap-2">
                {data.techniques.map((t) => (
                  <EntityLink
                    key={t.attackId}
                    type="technique"
                    attackId={t.attackId}
                    name={t.name}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Groups */}
          {data.groups.length > 0 && (
            <section>
              <SectionHeader label="Groups" count={data.groups.length} />
              <div className="flex flex-wrap gap-2">
                {data.groups.map((g) => (
                  <EntityLink
                    key={g.attackId}
                    type="group"
                    attackId={g.attackId}
                    name={g.name}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Software */}
          {data.software.length > 0 && (
            <section>
              <SectionHeader label="Software" count={data.software.length} />
              <div className="flex flex-wrap gap-2">
                {data.software.map((s) => (
                  <EntityLink
                    key={s.attackId}
                    type="software"
                    attackId={s.attackId}
                    name={s.name}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Mitigations */}
          {data.mitigations.length > 0 && (
            <section>
              <SectionHeader label="Mitigations" count={data.mitigations.length} />
              <div className="flex flex-wrap gap-2">
                {data.mitigations.map((m) => (
                  <EntityLink
                    key={m.attackId}
                    type="mitigation"
                    attackId={m.attackId}
                    name={m.name}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Campaigns */}
          {data.campaigns.length > 0 && (
            <section>
              <SectionHeader label="Campaigns" count={data.campaigns.length} />
              <div className="flex flex-wrap gap-2">
                {data.campaigns.map((c) => (
                  <EntityLink
                    key={c.attackId}
                    type="campaign"
                    attackId={c.attackId}
                    name={c.name}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Data Sources */}
          {data.data_sources.length > 0 && (
            <section>
              <SectionHeader label="Data Sources" count={data.data_sources.length} />
              <div className="flex flex-wrap gap-2">
                {data.data_sources.map((ds) => (
                  <EntityLink
                    key={ds.attackId}
                    type="data_source"
                    attackId={ds.attackId}
                    name={ds.name}
                  />
                ))}
              </div>
            </section>
          )}
        </div>
      )}
    </div>
  );
}
