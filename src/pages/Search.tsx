import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import { useSearch } from '../hooks/useApi';
import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';
import type { EntityType } from '../lib/types';

const ENTITY_PATH: Record<EntityType, string> = {
  technique: 'techniques',
  group: 'groups',
  software: 'software',
  mitigation: 'mitigations',
  campaign: 'campaigns',
  data_source: 'data-sources',
  tactic: 'tactics',
};

const ENTITY_COLOR: Record<EntityType, string> = {
  technique: 'text-[#64ffda]',
  group: 'text-[#f97316]',
  software: 'text-[#a78bfa]',
  mitigation: 'text-[#34d399]',
  campaign: 'text-[#60a5fa]',
  data_source: 'text-[#f472b6]',
  tactic: 'text-[#fbbf24]',
};

const EXAMPLE_CHIPS = ['APT29', 'T1059', 'Mimikatz', 'Phishing'];

function SectionHeader({ label, count }: { label: string; count: number }) {
  return (
    <div className="flex items-center gap-3 mb-2">
      <h2 className="text-sm font-semibold text-[#ccd6f6] uppercase tracking-wider">
        {label}
      </h2>
      <span className="text-xs font-semibold text-[#64ffda] bg-[#64ffda18] border border-[#64ffda33] px-2 py-0.5 rounded-full tabular-nums">
        {count}
      </span>
    </div>
  );
}

/** Compact list row for a single search result */
function ResultRow({
  attackId,
  name,
  type,
  context,
}: {
  attackId: string;
  name: string;
  type: EntityType;
  context?: string;
}) {
  const path = ENTITY_PATH[type];
  const color = ENTITY_COLOR[type];
  return (
    <Link
      to={`/${path}/${attackId}`}
      className="flex items-center gap-3 py-2 px-3 rounded-md hover:bg-[#64ffda0a] transition-colors duration-100 group"
    >
      <span className={`font-mono text-xs w-24 shrink-0 ${color}`}>{attackId}</span>
      <span className="text-sm text-[#ccd6f6] group-hover:text-white truncate flex-1">{name}</span>
      {context && (
        <span className="text-xs text-[#8892b0] truncate max-w-[200px] shrink-0 hidden sm:block">
          {context}
        </span>
      )}
    </Link>
  );
}

export function Search() {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const q = searchParams.get('q') ?? '';

  const { data, isLoading, error } = useSearch(q);

  const totalCount =
    (data?.techniques.length ?? 0) +
    (data?.groups.length ?? 0) +
    (data?.software.length ?? 0) +
    (data?.mitigations.length ?? 0) +
    (data?.campaigns.length ?? 0) +
    (data?.data_sources.length ?? 0);

  function setQuery(term: string) {
    navigate(`/search?q=${encodeURIComponent(term)}`);
  }

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

      {/* Example chips — shown when no query (FIX 27) */}
      {!q && (
        <div className="space-y-2">
          <p className="text-xs text-[#8892b0]">Try searching for:</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLE_CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                onClick={() => setQuery(chip)}
                className="px-3 py-1.5 text-xs rounded-md border border-[#64ffda33] text-[#64ffda] bg-[#64ffda0a] hover:bg-[#64ffda18] transition-colors"
              >
                {chip}
              </button>
            ))}
          </div>
        </div>
      )}

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
      {!isLoading && !error && data && totalCount === 0 && q.trim().length >= 3 && (
        <div className="space-y-3">
          <p className="text-[#8892b0] text-sm">No results found for &ldquo;{q}&rdquo;.</p>
          <div className="flex flex-wrap gap-2">
            {EXAMPLE_CHIPS.map((chip) => (
              <button
                key={chip}
                type="button"
                onClick={() => setQuery(chip)}
                className="px-3 py-1.5 text-xs rounded-md border border-[#2a2a4a] text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08] transition-colors"
              >
                {chip}
              </button>
            ))}
          </div>
        </div>
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

          {/* Techniques — compact list rows (FIX 26) */}
          {data.techniques.length > 0 && (
            <section>
              <SectionHeader label="Techniques" count={data.techniques.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.techniques.map((t) => (
                  <ResultRow
                    key={t.attackId}
                    attackId={t.attackId}
                    name={t.name}
                    type="technique"
                    context={(t as { tactics?: string[] }).tactics?.[0]}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Groups */}
          {data.groups.length > 0 && (
            <section>
              <SectionHeader label="Groups" count={data.groups.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.groups.map((g) => (
                  <ResultRow
                    key={g.attackId}
                    attackId={g.attackId}
                    name={g.name}
                    type="group"
                    context={(g as { country?: string }).country}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Software */}
          {data.software.length > 0 && (
            <section>
              <SectionHeader label="Software" count={data.software.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.software.map((s) => (
                  <ResultRow
                    key={s.attackId}
                    attackId={s.attackId}
                    name={s.name}
                    type="software"
                    context={(s as { type?: string }).type}
                  />
                ))}
              </div>
            </section>
          )}

          {/* Mitigations */}
          {data.mitigations.length > 0 && (
            <section>
              <SectionHeader label="Mitigations" count={data.mitigations.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.mitigations.map((m) => (
                  <ResultRow
                    key={m.attackId}
                    attackId={m.attackId}
                    name={m.name}
                    type="mitigation"
                  />
                ))}
              </div>
            </section>
          )}

          {/* Campaigns */}
          {data.campaigns.length > 0 && (
            <section>
              <SectionHeader label="Campaigns" count={data.campaigns.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.campaigns.map((c) => (
                  <ResultRow
                    key={c.attackId}
                    attackId={c.attackId}
                    name={c.name}
                    type="campaign"
                  />
                ))}
              </div>
            </section>
          )}

          {/* Data Sources */}
          {data.data_sources.length > 0 && (
            <section>
              <SectionHeader label="Data Sources" count={data.data_sources.length} />
              <div className="bg-[#16213e] border border-[#2a2a4a] rounded-lg divide-y divide-[#2a2a4a]">
                {data.data_sources.map((ds) => (
                  <ResultRow
                    key={ds.attackId}
                    attackId={ds.attackId}
                    name={ds.name}
                    type="data_source"
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
