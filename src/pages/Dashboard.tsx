import { useNavigate, Link } from 'react-router-dom';
import { usePageTitle } from '../hooks/usePageTitle';
import { useDashboard, useReports } from '../hooks/useApi';
import { useSector } from '../contexts/SectorContext';
import { useDomain } from '../contexts/DomainContext';
import { PageHeader } from '../components/layout/PageHeader';
import { StatCard } from '../components/shared/StatCard';
import { EntityLink } from '../components/shared/EntityLink';
import { TacticBarChart } from '../components/charts/TacticBarChart';
import { SectorPieChart } from '../components/charts/SectorPieChart';
import { isSafeUrl } from '../lib/urlSafety';

// ── Icon components (inline SVG, no extra deps) ───────────────────────────────

function IconShield() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
}

function IconUsers() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
    </svg>
  );
}

function IconCode() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  );
}

function IconFlag() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 3v1.5M3 21v-6m0 0l2.77-.693a9 9 0 016.208.682l.108.054a9 9 0 006.086.71l3.114-.732a48.524 48.524 0 01-.005-10.499l-3.11.732a9 9 0 01-6.085-.711l-.108-.054a9 9 0 00-6.208-.682L3 4.5M3 15V4.5" />
    </svg>
  );
}

function IconLock() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );
}

function IconDatabase() {
  return (
    <svg className="w-5 h-5" fill="none" stroke="currentColor" strokeWidth={1.5} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
    </svg>
  );
}

function IconExternalLink() {
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
    </svg>
  );
}

function IconArrowRight() {
  return (
    <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
    </svg>
  );
}

// ── Utility ───────────────────────────────────────────────────────────────────

function formatSeeded(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatReportDate(iso: string | null): string {
  if (!iso) return '—';
  return new Date(iso).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
  });
}

const SOURCE_COLOR: Record<string, string> = {
  otx: 'text-[var(--accent-teal)] bg-[var(--teal-ghost)] border-[#64ffda30]',
  dfir_report: 'text-[var(--accent-orange)] bg-[#f9731610] border-[#f9731630]',
  unit42: 'text-[var(--accent-blue)] bg-[#60a5fa10] border-[#60a5fa30]',
  microsoft_security: 'text-[var(--accent-blue)] bg-[#60a5fa10] border-[#60a5fa30]',
  talos: 'text-[var(--accent-purple)] bg-[#a78bfa10] border-[#a78bfa30]',
};

// ── Quick links config ─────────────────────────────────────────────────────────

const QUICK_LINKS = [
  { label: 'ATT&CK Matrix', href: '/matrix', color: 'text-[var(--accent-teal)]', desc: 'Full technique grid' },
  { label: 'CTI Reports', href: '/cti/reports', color: 'text-[var(--accent-orange)]', desc: 'Latest threat intel' },
  { label: 'Sigma Rules', href: '/cti/sigma', color: 'text-[var(--accent-purple)]', desc: 'Detection rules' },
  { label: 'IOCs', href: '/cti/iocs', color: 'text-[var(--accent-blue)]', desc: 'Indicators of compromise' },
  { label: 'NIST Controls', href: '/frameworks/nist', color: 'text-[var(--accent-green)]', desc: 'SP 800-53 mappings' },
  { label: 'ENGAGE', href: '/frameworks/engage', color: 'text-[var(--accent-yellow)]', desc: 'Defensive activities' },
];

// ── Skeleton components ───────────────────────────────────────────────────────

function VersionBannerSkeleton() {
  return (
    <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg px-5 py-3 flex items-center justify-between animate-pulse">
      <div className="h-4 w-48 rounded bg-[var(--border-color)]" />
      <div className="h-4 w-32 rounded bg-[var(--border-color)]" />
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export function Dashboard() {
  usePageTitle('Overview');

  const navigate = useNavigate();
  const { sectorParam } = useSector();
  const { domain, domainParam } = useDomain();
  const isAllDomains = domain === 'all';
  const { data, isLoading, error } = useDashboard({ ...sectorParam, ...domainParam });
  const { data: reportsData, isLoading: reportsLoading } = useReports({
    limit: '5',
    since: new Date(Date.now() - 7 * 86400000).toISOString().split('T')[0],
  });

  // ── Skeleton ────────────────────────────────────────────────────────────────

  if (isLoading) {
    return (
      <div className="space-y-6">
        {/* Version banner skeleton */}
        <div className="h-7 w-48 rounded bg-[var(--surface-card)] animate-pulse" />
        <VersionBannerSkeleton />

        {/* Stat cards skeleton */}
        <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 space-y-3 animate-pulse"
            >
              <div className="flex justify-between">
                <div className="h-7 w-14 rounded bg-[var(--border-color)]" />
                <div className="h-5 w-5 rounded bg-[var(--border-color)]" />
              </div>
              <div className="h-3 w-20 rounded bg-[var(--border-color)]" />
              <div className="h-3 w-12 rounded bg-[var(--border-color)]" />
            </div>
          ))}
        </div>

        {/* Chart row skeleton */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {Array.from({ length: 2 }).map((_, i) => (
            <div
              key={i}
              className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 animate-pulse"
            >
              <div className="h-4 w-40 rounded bg-[var(--border-color)] mb-4" />
              <div className="h-52 rounded bg-[var(--border-color)]" />
            </div>
          ))}
        </div>

        {/* Bottom row skeleton */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className={`bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 animate-pulse ${i === 0 ? 'xl:col-span-2' : ''}`}
            >
              <div className="h-4 w-44 rounded bg-[var(--border-color)] mb-4" />
              <div className="space-y-2.5">
                {Array.from({ length: 5 }).map((_, j) => (
                  <div key={j} className="flex items-center justify-between py-1.5">
                    <div className="h-3 w-32 rounded bg-[var(--border-color)]" />
                    <div className="h-3 w-10 rounded bg-[var(--border-color)]" />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  // ── Error state ──────────────────────────────────────────────────────────────

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--accent-orange)]">
        Failed to load dashboard data.
      </div>
    );
  }

  const { stats, topGroups, topTechniques, tacticDistribution, sectorBreakdown, attackVersion } = data;

  const recentReports = reportsData?.data ?? [];

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="space-y-6">

      {/* Page header */}
      <PageHeader
        title="Dashboard"
        subtitle="MITRE ATT&CK knowledge base overview"
      />

      {/* ── ATT&CK version banner ── */}
      {attackVersion && (
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg px-5 py-3 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
                {attackVersion.domain === 'atlas-attack' ? 'ATLAS Version' : 'ATT&CK Version'}
              </span>
              <span className="text-sm font-bold text-[var(--accent-teal)] tabular-nums">
                {isAllDomains ? '—' : `v${attackVersion.attackVersion}`}
              </span>
            </div>
            <div className="w-px h-4 bg-[var(--border-color)]" />
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
                Domain
              </span>
              <span className="text-sm font-semibold text-[var(--text-primary)]">
                {isAllDomains ? '—' : attackVersion.domain}
              </span>
            </div>
            <div className="w-px h-4 bg-[var(--border-color)]" />
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-[var(--text-secondary)] uppercase tracking-wide">
                Last Seeded
              </span>
              <span className="text-sm text-[var(--text-secondary)]">
                {isAllDomains ? '—' : formatSeeded(attackVersion.seededAt)}
              </span>
            </div>
          </div>
          <a
            href={attackVersion.domain === 'atlas-attack' ? 'https://atlas.mitre.org/' : 'https://attack.mitre.org/'}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
          >
            {attackVersion.domain === 'atlas-attack' ? 'MITRE ATLAS' : 'MITRE ATT&CK'}
            <IconExternalLink />
          </a>
        </div>
      )}

      {/* ── Stat cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
        <StatCard
          label="Techniques"
          value={stats.techniqueCount}
          accent="text-[var(--accent-teal)]"
          href="/techniques"
          hoverBorder="hover:border-[var(--accent-teal)]"
          hoverBg="hover:bg-[#64ffda06]"
          icon={<IconShield />}
          description="ATT&CK techniques"
        />
        <StatCard
          label="Groups"
          value={stats.groupCount}
          accent="text-[var(--accent-orange)]"
          href="/groups"
          hoverBorder="hover:border-[#f97316]"
          hoverBg="hover:bg-[#f9731606]"
          icon={<IconUsers />}
          description="Threat actor groups"
        />
        <StatCard
          label="Software"
          value={stats.softwareCount}
          accent="text-[var(--accent-purple)]"
          href="/software"
          hoverBorder="hover:border-[#a78bfa]"
          hoverBg="hover:bg-[#a78bfa06]"
          icon={<IconCode />}
          description="Malware &amp; tools"
        />
        <StatCard
          label="Campaigns"
          value={stats.campaignCount}
          accent="text-[var(--accent-blue)]"
          href="/campaigns"
          hoverBorder="hover:border-[#60a5fa]"
          hoverBg="hover:bg-[#60a5fa06]"
          icon={<IconFlag />}
          description="Named campaigns"
        />
        <StatCard
          label="Mitigations"
          value={stats.mitigationCount}
          accent="text-[var(--accent-green)]"
          href="/mitigations"
          hoverBorder="hover:border-[#34d399]"
          hoverBg="hover:bg-[#34d39906]"
          icon={<IconLock />}
          description="Defensive controls"
        />
        <StatCard
          label="Data Sources"
          value={stats.dataSourceCount}
          accent="text-[var(--accent-neutral)]"
          href="/data-sources"
          hoverBorder="hover:border-[#94a3b8]"
          hoverBg="hover:bg-[#94a3b806]"
          icon={<IconDatabase />}
          description="Detection sources"
        />
      </div>

      {/* ── Middle row: top groups + techniques + recent reports ── */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">

        {/* Top 10 groups */}
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Top 10 Groups</h2>
            <Link to="/groups" className="text-xs text-[var(--accent-orange)] hover:underline">View all</Link>
          </div>
          {topGroups.length > 0 ? (
            <div className="space-y-1">
              {topGroups.slice(0, 10).map((g, i) => (
                <div key={g.attackId} className="flex items-center justify-between py-1.5 border-b border-[var(--border-color)] last:border-0">
                  <div className="flex items-center gap-3 min-w-0">
                    <span className={`text-xs font-bold font-mono w-5 text-right shrink-0 ${i === 0 ? 'text-[var(--accent-yellow)]' : i === 1 ? 'text-[var(--text-secondary)]' : i === 2 ? 'text-[var(--accent-orange)]' : 'text-[var(--text-secondary)]'}`}>
                      {i + 1}
                    </span>
                    <EntityLink type="group" attackId={g.attackId} name={g.name} />
                  </div>
                  <span className="ml-2 text-sm font-semibold text-[var(--accent-orange)] tabular-nums shrink-0">{g.techniqueCount}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[var(--text-secondary)] text-sm">
              {domain === 'atlas-attack' ? 'ATLAS does not track threat groups.' : 'No group data available.'}
            </p>
          )}
        </div>

        {/* Most targeted techniques */}
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">
              Most Targeted Techniques
            </h2>
            <Link to="/techniques" className="text-xs text-[var(--accent-teal)] hover:underline">View all</Link>
          </div>
          {topTechniques.length > 0 ? (
            <div className="space-y-1">
              {topTechniques.map((t, i) => (
                <div
                  key={t.attackId}
                  className="flex items-center justify-between py-1.5 border-b border-[var(--border-color)] last:border-0"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <span
                      className={`
                        text-xs font-bold font-mono w-5 text-right shrink-0
                        ${i === 0 ? 'text-[var(--accent-yellow)]' : i === 1 ? 'text-[var(--text-secondary)]' : i === 2 ? 'text-[var(--accent-orange)]' : 'text-[var(--text-secondary)]'}
                      `}
                    >
                      {i + 1}
                    </span>
                    <EntityLink
                      type="technique"
                      attackId={t.attackId}
                      name={t.name}
                    />
                  </div>
                  <span className="ml-2 text-sm font-semibold text-[var(--accent-teal)] tabular-nums shrink-0">
                    {t.groupCount} groups
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[var(--text-secondary)] text-sm">No technique data available.</p>
          )}
        </div>

        {/* Recent threat reports + quick links */}
        <div className="flex flex-col gap-6">

          {/* Recent reports */}
          <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5 flex-1">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-[var(--text-primary)]">
                Recent Reports
              </h2>
              <Link
                to="/cti/reports"
                className="flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--accent-teal)] transition-colors"
              >
                All reports
                <IconArrowRight />
              </Link>
            </div>

            {reportsLoading ? (
              <div className="space-y-2.5">
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="flex justify-between items-start animate-pulse">
                    <div className="h-3 w-44 rounded bg-[var(--border-color)]" />
                    <div className="h-3 w-10 rounded bg-[var(--border-color)]" />
                  </div>
                ))}
              </div>
            ) : recentReports.length === 0 ? (
              <p className="text-[var(--text-secondary)] text-xs">
                No recent reports. Trigger a{' '}
                <Link to="/cti/feed-status" className="text-[var(--accent-teal)] hover:underline">
                  feed sync
                </Link>
                .
              </p>
            ) : (
              <div className="space-y-2">
                {recentReports.map((r) => (
                  <div key={r.id} className="group">
                    <a
                      href={isSafeUrl(r.url) ? r.url : '#'}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-start justify-between gap-2 py-1.5 border-b border-[var(--border-color)] last:border-0"
                    >
                      <div className="min-w-0">
                        <p className="text-xs text-[var(--text-primary)] group-hover:text-[var(--accent-teal)] transition-colors line-clamp-2 leading-relaxed">
                          {r.title}
                        </p>
                        <div className="flex items-center gap-2 mt-1">
                          <span
                            className={`
                              inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border
                              ${SOURCE_COLOR[r.source] ?? 'text-[var(--text-secondary)] bg-[#8892b010] border-[#8892b030]'}
                            `}
                          >
                            {r.source}
                          </span>
                          {r.technique_count > 0 && (
                            <span className="text-[10px] text-[var(--accent-teal)] font-mono">
                              {r.technique_count} ttps
                            </span>
                          )}
                        </div>
                      </div>
                      <span className="text-[10px] text-[var(--text-secondary)] shrink-0 mt-0.5">
                        {formatReportDate(r.published_at)}
                      </span>
                    </a>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Quick links */}
          <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
            <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">
              Quick Links
            </h2>
            <div className="grid grid-cols-2 gap-2">
              {QUICK_LINKS.map((ql) => (
                <Link
                  key={ql.href}
                  to={ql.href}
                  className="flex flex-col gap-0.5 rounded-md px-3 py-2.5 border border-[var(--border-color)] hover:border-[var(--border-hover)] hover:bg-[var(--hover-overlay)] transition-all group"
                >
                  <span className={`text-xs font-semibold ${ql.color} group-hover:brightness-110`}>
                    {ql.label}
                  </span>
                  <span className="text-[10px] text-[var(--text-secondary)]">{ql.desc}</span>
                </Link>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* ── Charts row (bottom) ── */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Techniques per Tactic</h2>
            <Link to="/tactics" className="flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--accent-yellow)] transition-colors">
              All tactics <IconArrowRight />
            </Link>
          </div>
          <p className="text-xs text-[var(--text-secondary)] mb-3">Click a bar to explore that tactic</p>
          {tacticDistribution.length > 0 ? (
            <TacticBarChart data={tacticDistribution} onBarClick={(tacticId) => navigate(`/tactics/${tacticId}`)} />
          ) : (
            <p className="text-[var(--text-secondary)] text-sm">No data available.</p>
          )}
        </div>
        <div className="bg-[var(--surface-card)] border border-[var(--border-color)] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-[var(--text-primary)]">Groups by Sector</h2>
            <Link to="/sectors" className="flex items-center gap-1 text-xs text-[var(--text-secondary)] hover:text-[var(--accent-pink)] transition-colors">
              All sectors <IconArrowRight />
            </Link>
          </div>
          {sectorBreakdown.length > 0 ? (
            <SectorPieChart data={sectorBreakdown} />
          ) : (
            <p className="text-[var(--text-secondary)] text-sm">No sector data available.</p>
          )}
        </div>
      </div>
    </div>
  );
}
