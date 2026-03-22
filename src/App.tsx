import { Routes, Route, Outlet } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { SearchBar } from './components/layout/SearchBar';

// Pages
import { Dashboard } from './pages/Dashboard';
import { Matrix } from './pages/Matrix';
import { TechniquesList } from './pages/TechniquesList';
import { TechniqueDetail } from './pages/TechniqueDetail';
import { GroupsList } from './pages/GroupsList';
import { GroupDetail } from './pages/GroupDetail';
import { CampaignsList } from './pages/CampaignsList';
import { CampaignDetail } from './pages/CampaignDetail';
import { SoftwareList } from './pages/SoftwareList';
import { SoftwareDetail } from './pages/SoftwareDetail';
import { DataSourcesList } from './pages/DataSourcesList';
import { DataSourceDetail } from './pages/DataSourceDetail';
import { MitigationsList } from './pages/MitigationsList';
import { MitigationDetail } from './pages/MitigationDetail';
import { TacticsList } from './pages/TacticsList';
import { TacticDetail } from './pages/TacticDetail';
import { SectorsList } from './pages/SectorsList';
import { SectorDetail } from './pages/SectorDetail';
import { Relationships } from './pages/Relationships';
import { Search } from './pages/Search';
// CTI pages
import { ReportsList } from './pages/ReportsList';
import { IocsList } from './pages/IocsList';
import { SigmaList } from './pages/SigmaList';
import { FeedStatus } from './pages/FeedStatus';

/** Root layout — sidebar + top bar + page content */
function Layout() {
  return (
    <div className="flex min-h-screen bg-[#0a0a1a]">
      <Sidebar />

      {/* Main area pushed right of the fixed sidebar */}
      <div className="flex-1 flex flex-col ml-60 min-h-screen">
        {/* Top header bar */}
        <header className="sticky top-0 z-30 flex items-center gap-4 px-6 py-3 bg-[#0a0a1a] border-b border-[#2a2a4a]">
          <SearchBar />
        </header>

        {/* Page content */}
        <main className="flex-1 px-6 py-6 overflow-auto">
          <Outlet />
        </main>
      </div>
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
        {/* Dashboard */}
        <Route index element={<Dashboard />} />

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
        <Route path="relationships" element={<Relationships />} />

        {/* Search */}
        <Route path="search" element={<Search />} />

        {/* CTI Feed pages */}
        <Route path="cti/reports" element={<ReportsList />} />
        <Route path="cti/iocs" element={<IocsList />} />
        <Route path="cti/sigma" element={<SigmaList />} />
        <Route path="cti/feed-status" element={<FeedStatus />} />

        {/* 404 */}
        <Route path="*" element={<PlaceholderPage title="404 - Not Found" />} />
      </Route>
    </Routes>
  );
}
