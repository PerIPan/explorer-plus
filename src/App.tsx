import { lazy, Suspense, useState } from 'react';
import { Routes, Route, Outlet } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { SearchBar } from './components/layout/SearchBar';
import { RelationshipModel } from './components/relationships/RelationshipModel';

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
const ReportsList     = lazy(() => import('./pages/ReportsList').then((m) => ({ default: m.ReportsList })));
const IocsList        = lazy(() => import('./pages/IocsList').then((m) => ({ default: m.IocsList })));
const SigmaList       = lazy(() => import('./pages/SigmaList').then((m) => ({ default: m.SigmaList })));
const FeedStatus      = lazy(() => import('./pages/FeedStatus').then((m) => ({ default: m.FeedStatus })));
// Framework pages
const NistControls    = lazy(() => import('./pages/NistControls').then((m) => ({ default: m.NistControls })));
const EngageActivities = lazy(() => import('./pages/EngageActivities').then((m) => ({ default: m.EngageActivities })));
const ReactActions    = lazy(() => import('./pages/ReactActions').then((m) => ({ default: m.ReactActions })));

/** Simple spinner used as Suspense fallback */
function LoadingSpinner() {
  return (
    <div className="flex items-center justify-center h-64 text-[#8892b0]">
      <span className="inline-block w-5 h-5 border-2 border-[#64ffda33] border-t-[#64ffda] rounded-full animate-spin mr-2" />
      Loading...
    </div>
  );
}

/** Root layout — sidebar + top bar + page content */
function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [modelOpen, setModelOpen] = useState(false);

  return (
    <div className="flex min-h-screen bg-[#0a0a1a]">
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
      <div className="flex-1 flex flex-col lg:ml-60 min-h-screen">
        {/* Top header bar */}
        <header className="sticky top-0 z-30 flex items-center gap-4 px-6 py-3 bg-[#16213e] shadow-sm border-b border-[#2a2a4a]">
          {/* Hamburger — visible only below lg */}
          <button
            type="button"
            aria-label="Open navigation menu"
            onClick={() => setSidebarOpen(true)}
            className="lg:hidden flex-shrink-0 p-1 rounded-md text-[#8892b0] hover:text-[#ccd6f6] hover:bg-[#ffffff08] transition-colors"
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
            className="flex-shrink-0 px-3 py-1.5 text-xs rounded-md border border-[#2a2a4a] text-[#8892b0] hover:text-[#64ffda] hover:border-[#64ffda33] transition-colors"
            title="ATT&CK relationship model"
          >
            Model
          </button>
        </header>

        {/* Page content */}
        <main className="flex-1 px-6 py-6 overflow-auto">
          <Outlet />
        </main>
      </div>

      <RelationshipModel open={modelOpen} onClose={() => setModelOpen(false)} />
    </div>
  );
}

/** Placeholder for CTI pages not yet implemented */
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[#64ffda] text-4xl font-light mb-2">{title}</div>
        <div className="text-[#8892b0] text-sm">Coming soon</div>
      </div>
    </div>
  );
}

export default function App() {
  return (
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
          <Route path="cti/reports" element={<ReportsList />} />
          <Route path="cti/iocs" element={<IocsList />} />
          <Route path="cti/sigma" element={<SigmaList />} />
          <Route path="cti/feed-status" element={<FeedStatus />} />

          {/* Framework pages */}
          <Route path="frameworks/nist" element={<NistControls />} />
          <Route path="frameworks/engage" element={<EngageActivities />} />
          <Route path="frameworks/react" element={<ReactActions />} />

          {/* 404 */}
          <Route path="*" element={<PlaceholderPage title="404 - Not Found" />} />
        </Route>
      </Route>
    </Routes>
  );
}
