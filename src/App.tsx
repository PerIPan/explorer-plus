import { lazy, Suspense, useState, useEffect } from 'react';
// react-router-dom removed — routing handled by Next.js app/ directory
import { Sidebar } from './components/layout/Sidebar';
import { SearchBar } from './components/layout/SearchBar';
import { SectorProvider } from './contexts/SectorContext';
import { DomainProvider } from './contexts/DomainContext';
import { ThemeProvider, useTheme } from './contexts/ThemeContext';
import { RelationshipModel } from './components/relationships/RelationshipModel';
import { ErrorBoundary } from './components/shared/ErrorBoundary';
import { Analytics } from '@vercel/analytics/react';
import { DiamondLoader } from './components/shared/FoldingDiamond';

// Lazy-loaded pages
const Dashboard       = lazy(() => import('./views/Dashboard').then((m) => ({ default: m.Dashboard })));
const Matrix          = lazy(() => import('./views/Matrix').then((m) => ({ default: m.Matrix })));
const TechniquesList  = lazy(() => import('./views/TechniquesList').then((m) => ({ default: m.TechniquesList })));
const TechniqueDetail = lazy(() => import('./views/TechniqueDetail').then((m) => ({ default: m.TechniqueDetail })));
const GroupsList      = lazy(() => import('./views/GroupsList').then((m) => ({ default: m.GroupsList })));
const GroupDetail     = lazy(() => import('./views/GroupDetail').then((m) => ({ default: m.GroupDetail })));
const CampaignsList   = lazy(() => import('./views/CampaignsList').then((m) => ({ default: m.CampaignsList })));
const CampaignDetail  = lazy(() => import('./views/CampaignDetail').then((m) => ({ default: m.CampaignDetail })));
const SoftwareList    = lazy(() => import('./views/SoftwareList').then((m) => ({ default: m.SoftwareList })));
const SoftwareDetail  = lazy(() => import('./views/SoftwareDetail').then((m) => ({ default: m.SoftwareDetail })));
const DataSourcesList = lazy(() => import('./views/DataSourcesList').then((m) => ({ default: m.DataSourcesList })));
const DataSourceDetail = lazy(() => import('./views/DataSourceDetail').then((m) => ({ default: m.DataSourceDetail })));
const MitigationsList = lazy(() => import('./views/MitigationsList').then((m) => ({ default: m.MitigationsList })));
const MitigationDetail = lazy(() => import('./views/MitigationDetail').then((m) => ({ default: m.MitigationDetail })));
const TacticsList     = lazy(() => import('./views/TacticsList').then((m) => ({ default: m.TacticsList })));
const TacticDetail    = lazy(() => import('./views/TacticDetail').then((m) => ({ default: m.TacticDetail })));
const SectorsList     = lazy(() => import('./views/SectorsList').then((m) => ({ default: m.SectorsList })));
const SectorDetail    = lazy(() => import('./views/SectorDetail').then((m) => ({ default: m.SectorDetail })));
const Relationships   = lazy(() => import('./views/Relationships').then((m) => ({ default: m.Relationships })));
const Search          = lazy(() => import('./views/Search').then((m) => ({ default: m.Search })));
// CTI pages
const CvesList        = lazy(() => import('./views/CvesList').then((m) => ({ default: m.CvesList })));
const CveDetail       = lazy(() => import('./views/CveDetail').then((m) => ({ default: m.CveDetail })));
const ReportsList     = lazy(() => import('./views/ReportsList').then((m) => ({ default: m.ReportsList })));
const IocsList        = lazy(() => import('./views/IocsList').then((m) => ({ default: m.IocsList })));
const SigmaList       = lazy(() => import('./views/SigmaList').then((m) => ({ default: m.SigmaList })));
const FeedStatus      = lazy(() => import('./views/FeedStatus').then((m) => ({ default: m.FeedStatus })));
// Framework pages
const NistControls    = lazy(() => import('./views/NistControls').then((m) => ({ default: m.NistControls })));
const EngageActivities = lazy(() => import('./views/EngageActivities').then((m) => ({ default: m.EngageActivities })));
const ReactActions    = lazy(() => import('./views/ReactActions').then((m) => ({ default: m.ReactActions })));
const VerisCategories = lazy(() => import('./views/VerisCategories').then((m) => ({ default: m.VerisCategories })));
const OwaspTop10      = lazy(() => import('./views/OwaspTop10').then((m) => ({ default: m.OwaspTop10 })));
const CloudControls   = lazy(() => import('./views/CloudControls').then((m) => ({ default: m.CloudControls })));
const AtomicTests     = lazy(() => import('./views/AtomicTests').then((m) => ({ default: m.AtomicTests })));
const DetectionStrategies = lazy(() => import('./views/DetectionStrategies').then((m) => ({ default: m.DetectionStrategies })));
const ApplicationsList = lazy(() => import('./views/ApplicationsList').then((m) => ({ default: m.ApplicationsList })));
// Extended Intel pages
const ExternalActors  = lazy(() => import('./views/ExternalActors').then((m) => ({ default: m.ExternalActors })));

/** Simple spinner used as Suspense fallback */
function LoadingSpinner() {
  return <DiamondLoader text="Loading..." />;
}

/** VirusTotal trust badge */
function VtBadge() {
  const [data, setData] = useState<{ malicious: number; total: number; reportUrl: string } | null>(null);
  useEffect(() => {
    fetch('/api/v1/site-health').then(r => r.json()).then(d => {
      if (d.available) setData({ malicious: d.malicious, total: d.total, reportUrl: d.reportUrl });
    }).catch(() => {});
  }, []);
  if (!data) return null;
  return (
    <a
      href={data.reportUrl}
      target="_blank"
      rel="noopener noreferrer"
      className="flex-shrink-0 flex items-center gap-1.5 px-2.5 py-1 text-[10px] rounded-md border border-emerald-200 dark:border-emerald-800 text-emerald-600 dark:text-emerald-400 hover:border-emerald-400 transition-colors"
      title={`VirusTotal: ${data.malicious}/${data.total} detections — click to view full report`}
    >
      <svg viewBox="0 0 24 24" className="w-3.5 h-3.5" fill="none" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
      {data.malicious}/{data.total}
    </a>
  );
}

/** Theme toggle — sun/moon icon */
function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button
      type="button"
      onClick={toggle}
      data-print-hide
      className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
    >
      {theme === 'dark' ? (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
        </svg>
      ) : (
        <svg className="w-4 h-4" fill="none" stroke="currentColor" strokeWidth={2} viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
        </svg>
      )}
    </button>
  );
}

/** Root layout — sidebar + top bar + page content */
function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);
  const [helpOpen, setHelpOpen] = useState(false);

  return (
    <DomainProvider>
    <SectorProvider>
    <div className="flex min-h-screen bg-[var(--surface-deep)]">
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      {/* Main area pushed right of the fixed sidebar on lg+ */}
      <div className="flex-1 flex flex-col lg:ml-52 min-h-screen">
        {/* Top header bar */}
        <header className="sticky top-0 z-30 flex items-center gap-2 md:gap-4 px-3 md:px-6 py-2 md:py-3 bg-[var(--surface-card)] shadow-sm border-b border-[var(--border-color)]">
          {/* Hamburger — visible only below lg */}
          <button
            type="button"
            aria-label="Open navigation menu"
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden flex-shrink-0 p-1 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)] transition-colors"
          >
            <svg
              className="w-5 h-5"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>
          <SearchBar />
          <button
            type="button"
            onClick={() => setModelOpen(true)}
            className="hidden md:block flex-shrink-0 px-3 py-1.5 text-xs rounded-md border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="ATT&CK data model — entity relationships"
          >
            Data Model
          </button>
          <div className="flex-1" />
          <div className="hidden md:block"><VtBadge /></div>
          <ThemeToggle />
          <button
            type="button"
            onClick={() => setHelpOpen(true)}
            data-print-hide
            className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="About this application"
          >
            ?
          </button>
        </header>

        {/* Page content */}
        <main className="flex-1 px-3 md:px-6 py-4 md:py-6 overflow-y-auto overflow-x-hidden">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>

        {/* Print-only watermark — bottom right */}
        <div className="print-watermark hidden fixed bottom-4 right-6 items-center gap-2 opacity-60" style={{ zIndex: 9999 }}>
          <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" width="18" height="18">
            <g transform="translate(16,16) rotate(45) translate(-11,-11)">
              <rect x="0" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.6"/>
              <rect x="11.2" y="0" width="10.8" height="10.8" fill="#0d9488" opacity="0.75"/>
              <rect x="11.2" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="0.88"/>
              <rect x="0" y="11.2" width="10.8" height="10.8" fill="#0d9488" opacity="1"/>
            </g>
          </svg>
          <span style={{ fontSize: '10px', color: '#64748b', fontWeight: 600, letterSpacing: '0.03em' }}>
            mitre-explorer.org
          </span>
        </div>
      </div>
      <Analytics />

      <RelationshipModel open={modelOpen} onClose={() => setModelOpen(false)} />

      {/* Help modal */}
      {helpOpen && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={() => setHelpOpen(false)}>
          <div
            className="bg-[var(--surface-deep)] border border-[var(--border-color)] rounded-xl shadow-2xl w-[95vw] max-w-[640px] max-h-[85vh] overflow-y-auto"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border-color)]">
              <h2 className="text-lg font-semibold text-[var(--text-primary)]">about MITRE Explorer Plus (CLA)</h2>
              <button onClick={() => setHelpOpen(false)} className="p-2 rounded-md text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--hover-overlay)]">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="px-6 py-5 space-y-4 text-sm text-[var(--text-primary)] leading-relaxed">
              <div className="flex justify-center pb-2">
                <img src="/diamond-favicon.svg" alt="MITRE Explorer Plus" className="w-12 h-12" />
              </div>
              <p>
                <strong>MITRE Explorer Plus</strong> — a multi-domain threat intelligence platform on{' '}
                <em>MITRE ATT&CK</em>. Single interface for adversary behavior, detection, compliance, and application security — enriched with CTI reports and CVE vulnerability data.
              </p>
              <ul className="space-y-2 pl-4 list-disc marker:text-[var(--accent-teal)]">
                <li><strong>Multi-domain ATT&CK + ATLAS</strong> — Enterprise, ICS, Mobile, ATLAS (AI/ML threats) with domain switcher + "All Domains" cross-domain view</li>
                <li><strong>A2A Agent Protocol v1.0</strong> — AI agents can query this knowledge base programmatically via the <a href="/.well-known/agent-card.json" target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline">Agent Card</a>. 13 skills, 50 req/day, no auth. Example: <em className="text-[var(--text-secondary)]">"ask mitre-explorer.org, using the A2A Google GenAI protocol, 'which Applications have been affected by new CVEs published in the previous week, show me the relevant Techniques. Also show me the latest 2-day threat reports. Render what you get as a response, for me to look at.'"</em> Powered by Gemini</li>
                <li><strong>Actor comparison</strong> — select up to 3 threat actors on the Matrix, see technique overlap color-coded, export as HTML</li>
                <li><strong>360 Views</strong> — search any entity, explore via Technique Map, Actor Profile, Software Map, Application Map, Sector Map, or D3 force graph</li>
                <li><strong>Applications</strong> — 7K+ vendor products linked to CVEs → CWE → CAPEC → ATT&CK techniques → threat groups. See which apps your adversaries target</li>
                <li><strong>Frameworks</strong> — OWASP Top 10 (Web 2021, ML 2023, LLM 2025), NIST 800-53, MITRE Engage, D3FEND, RE&CT, VERIS incident classification, Azure + GCP cloud controls</li>
                <li><strong>CVEs</strong> — since 2017, CISA KEV + NVD enrichment (CVSS scores), linked to ATT&CK techniques via CWE→CAPEC bridge + CTID hand-curated mappings</li>
                <li><strong>IOCs</strong> — OTX + ThreatFox + MalwareBazaar, enriched with VirusTotal verdicts and sandbox-derived techniques</li>
                <li><strong>Detection</strong> — Detection Strategies + Analytics (ATT&CK v18), SigmaHQ rules, Atomic Red Team tests, MITRE Caldera, D3FEND countermeasures</li>
                <li><strong>Threat actors</strong> — 191 ATT&CK groups + 514 ThaiCERT/ETDA actors with category inference</li>
                <li><strong>Data model</strong> — 20+ interconnected data sources: ATT&CK STIX, CVElistV5, CAPEC, NIST, CISA KEV, OTX, SigmaHQ, Atomic Red Team, D3FEND, VERIS, CTID</li>
                <li><strong>Sector + domain filters</strong> — narrow everything by industry and ATT&CK domain (AND logic)</li>
                <li><strong>Diamond Model</strong> — Adversary (Threat Actors) | Victim (Sectors) | Infrastructure (Applications) | Capability (Techniques)</li>
              </ul>
              <p className="text-[var(--text-secondary)] text-xs pt-2 border-t border-[var(--border-color)]">
                <span className="text-[var(--accent-teal)]">contact @ mitre-explorer.org</span>
                {' — '}Not affiliated with or endorsed by MITRE Corporation.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
    </SectorProvider>
    </DomainProvider>
  );
}

/** Placeholder for CTI pages not yet implemented */
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[var(--accent-teal)] text-4xl font-light mb-2">{title}</div>
        <div className="text-[var(--text-secondary)] text-sm">Coming soon</div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
    <Routes>
      <Route element={<Layout />}>
        <Route element={<Suspense fallback={<LoadingSpinner />}><Outlet /></Suspense>}>
          {/* Relationships is the default landing page */}
          <Route index element={<Relationships />} />
          <Route path="relationships" element={<Relationships />} />

          {/* Dashboard */}
          <Route path="dashboard" element={<Dashboard />} />

          {/* Matrix */}
          <Route path="matrix" element={<Matrix />} />

          {/* Techniques */}
          <Route path="techniques" element={<TechniquesList />} />
          <Route path="techniques/:attackId" element={<TechniqueDetail />} />

          {/* Groups */}
          <Route path="groups" element={<GroupsList />} />
          <Route path="groups/:attackId" element={<GroupDetail />} />

          {/* Campaigns */}
          <Route path="campaigns" element={<CampaignsList />} />
          <Route path="campaigns/:attackId" element={<CampaignDetail />} />

          {/* Software */}
          <Route path="software" element={<SoftwareList />} />
          <Route path="software/:attackId" element={<SoftwareDetail />} />

          {/* Data Sources */}
          <Route path="data-sources" element={<DataSourcesList />} />
          <Route path="data-sources/:attackId" element={<DataSourceDetail />} />

          {/* Mitigations */}
          <Route path="mitigations" element={<MitigationsList />} />
          <Route path="mitigations/:attackId" element={<MitigationDetail />} />

          {/* Tactics */}
          <Route path="tactics" element={<TacticsList />} />
          <Route path="tactics/:attackId" element={<TacticDetail />} />

          {/* Sectors */}
          <Route path="sectors" element={<SectorsList />} />
          <Route path="sectors/:sectorName" element={<SectorDetail />} />

          {/* Relationships */}

          {/* Search */}
          <Route path="search" element={<Search />} />

          {/* CTI Feed pages */}
          <Route path="cti/cves" element={<CvesList />} />
          <Route path="cti/cves/:cveId" element={<CveDetail />} />
          <Route path="cti/reports" element={<ReportsList />} />
          <Route path="cti/iocs" element={<IocsList />} />
          <Route path="cti/sigma" element={<SigmaList />} />
          <Route path="cti/feed-status" element={<FeedStatus />} />

          {/* Framework pages */}
          <Route path="frameworks/nist" element={<NistControls />} />
          <Route path="frameworks/engage" element={<EngageActivities />} />
          <Route path="frameworks/detection" element={<DetectionStrategies />} />
          <Route path="frameworks/owasp" element={<OwaspTop10 />} />
          <Route path="frameworks/owasp/:categoryId" element={<OwaspTop10 />} />
          <Route path="applications" element={<ApplicationsList />} />
          <Route path="frameworks/react" element={<ReactActions />} />
          <Route path="frameworks/veris" element={<VerisCategories />} />
          <Route path="frameworks/cloud" element={<CloudControls />} />
          <Route path="frameworks/atomic" element={<AtomicTests />} />

          {/* Extended Intel */}
          <Route path="external-actors" element={<ExternalActors />} />

          {/* 404 */}
          <Route path="*" element={<PlaceholderPage title="404 - Not Found" />} />
        </Route>
      </Route>
    </Routes>
    </ThemeProvider>
  );
}
