import { lazy, Suspense, useState } from 'react';
import { Routes, Route, Outlet } from 'react-router-dom';
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
const Dashboard       = lazy(() => import('./pages/Dashboard').then((m) => ({ default: m.Dashboard })));
const Matrix          = lazy(() => import('./pages/Matrix').then((m) => ({ default: m.Matrix })));
const TechniquesList  = lazy(() => import('./pages/TechniquesList').then((m) => ({ default: m.TechniquesList })));
const TechniqueDetail = lazy(() => import('./pages/TechniqueDetail').then((m) => ({ default: m.TechniqueDetail })));
const GroupsList      = lazy(() => import('./pages/GroupsList').then((m) => ({ default: m.GroupsList })));
const GroupDetail     = lazy(() => import('./pages/GroupDetail').then((m) => ({ default: m.GroupDetail })));
const CampaignsList   = lazy(() => import('./pages/CampaignsList').then((m) => ({ default: m.CampaignsList })));
const CampaignDetail  = lazy(() => import('./pages/CampaignDetail').then((m) => ({ default: m.CampaignDetail })));
const SoftwareList    = lazy(() => import('./pages/SoftwareList').then((m) => ({ default: m.SoftwareList })));
const SoftwareDetail  = lazy(() => import('./pages/SoftwareDetail').then((m) => ({ default: m.SoftwareDetail })));
const DataSourcesList = lazy(() => import('./pages/DataSourcesList').then((m) => ({ default: m.DataSourcesList })));
const DataSourceDetail = lazy(() => import('./pages/DataSourceDetail').then((m) => ({ default: m.DataSourceDetail })));
const MitigationsList = lazy(() => import('./pages/MitigationsList').then((m) => ({ default: m.MitigationsList })));
const MitigationDetail = lazy(() => import('./pages/MitigationDetail').then((m) => ({ default: m.MitigationDetail })));
const TacticsList     = lazy(() => import('./pages/TacticsList').then((m) => ({ default: m.TacticsList })));
const TacticDetail    = lazy(() => import('./pages/TacticDetail').then((m) => ({ default: m.TacticDetail })));
const SectorsList     = lazy(() => import('./pages/SectorsList').then((m) => ({ default: m.SectorsList })));
const SectorDetail    = lazy(() => import('./pages/SectorDetail').then((m) => ({ default: m.SectorDetail })));
const Relationships   = lazy(() => import('./pages/Relationships').then((m) => ({ default: m.Relationships })));
const Search          = lazy(() => import('./pages/Search').then((m) => ({ default: m.Search })));
// CTI pages
const CvesList        = lazy(() => import('./pages/CvesList').then((m) => ({ default: m.CvesList })));
const CveDetail       = lazy(() => import('./pages/CveDetail').then((m) => ({ default: m.CveDetail })));
const ReportsList     = lazy(() => import('./pages/ReportsList').then((m) => ({ default: m.ReportsList })));
const IocsList        = lazy(() => import('./pages/IocsList').then((m) => ({ default: m.IocsList })));
const SigmaList       = lazy(() => import('./pages/SigmaList').then((m) => ({ default: m.SigmaList })));
const FeedStatus      = lazy(() => import('./pages/FeedStatus').then((m) => ({ default: m.FeedStatus })));
// Framework pages
const NistControls    = lazy(() => import('./pages/NistControls').then((m) => ({ default: m.NistControls })));
const EngageActivities = lazy(() => import('./pages/EngageActivities').then((m) => ({ default: m.EngageActivities })));
const ReactActions    = lazy(() => import('./pages/ReactActions').then((m) => ({ default: m.ReactActions })));
const VerisCategories = lazy(() => import('./pages/VerisCategories').then((m) => ({ default: m.VerisCategories })));
const CloudControls   = lazy(() => import('./pages/CloudControls').then((m) => ({ default: m.CloudControls })));
const AtomicTests     = lazy(() => import('./pages/AtomicTests').then((m) => ({ default: m.AtomicTests })));
const DetectionStrategies = lazy(() => import('./pages/DetectionStrategies').then((m) => ({ default: m.DetectionStrategies })));
const ApplicationsList = lazy(() => import('./pages/ApplicationsList').then((m) => ({ default: m.ApplicationsList })));
// Extended Intel pages
const ExternalActors  = lazy(() => import('./pages/ExternalActors').then((m) => ({ default: m.ExternalActors })));

/** Simple spinner used as Suspense fallback */
function LoadingSpinner() {
  return <DiamondLoader text="Loading..." />;
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
        <header className="sticky top-0 z-30 flex items-center gap-4 px-6 py-3 bg-[var(--surface-card)] shadow-sm border-b border-[var(--border-color)]">
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
          <div className="flex-1" />
          <button
            type="button"
            onClick={() => setModelOpen(true)}
            className="flex-shrink-0 px-3 py-1.5 text-xs rounded-md border border-[var(--border-color)] text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:border-[var(--teal-dim)] transition-colors"
            title="ATT&CK data model — entity relationships"
          >
            Data Model
          </button>
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
        <main className="flex-1 px-6 py-6 overflow-auto">
          <ErrorBoundary>
            <Outlet />
          </ErrorBoundary>
        </main>
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
                <li><strong>Multi-domain ATT&CK</strong> — Enterprise, ICS, Mobile with domain switcher + "All Domains" cross-domain view</li>
                <li><strong>Actor comparison</strong> — select up to 3 threat actors on the Matrix, see technique overlap color-coded, export as HTML</li>
                <li><strong>360 Views</strong> — search any entity, explore via Technique Map, Actor Profile, Software Map, Application Map, Sector Map, or D3 force graph</li>
                <li><strong>Applications</strong> — 7K+ vendor products linked to CVEs → CWE → CAPEC → ATT&CK techniques → threat groups. See which apps your adversaries target</li>
                <li><strong>Frameworks</strong> — NIST 800-53, MITRE Engage, D3FEND, RE&CT, VERIS incident classification, Azure + GCP cloud controls</li>
                <li><strong>CVEs</strong> — CISA KEV + NVD enrichment (CVSS scores), linked to ATT&CK techniques via CWE→CAPEC bridge + CTID hand-curated mappings</li>
                <li><strong>IOCs</strong> — OTX + ThreatFox + MalwareBazaar, enriched with VirusTotal verdicts and sandbox-derived techniques</li>
                <li><strong>Detection</strong> — Detection Strategies + Analytics (ATT&CK v18), SigmaHQ rules, Atomic Red Team tests, MITRE Caldera, D3FEND countermeasures</li>
                <li><strong>Threat actors</strong> — 191 ATT&CK groups + 514 ThaiCERT/ETDA actors with category inference</li>
                <li><strong>Data model</strong> — 20+ interconnected data sources: ATT&CK STIX, CVElistV5, CAPEC, NIST, CISA KEV, OTX, SigmaHQ, Atomic Red Team, D3FEND, VERIS, CTID</li>
                <li><strong>Sector + domain filters</strong> — narrow everything by industry and ATT&CK domain (AND logic)</li>
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
