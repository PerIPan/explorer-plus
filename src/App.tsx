import { Routes, Route, Outlet } from 'react-router-dom';
import { Sidebar } from './components/layout/Sidebar';
import { SearchBar } from './components/layout/SearchBar';

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

/** Placeholder page used until real pages are built */
function PlaceholderPage({ title }: { title: string }) {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="text-[#64ffda] text-4xl font-light mb-2">
          {title}
        </div>
        <div className="text-[#8892b0] text-sm">Coming soon</div>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<PlaceholderPage title="Dashboard" />} />
        <Route path="matrix" element={<PlaceholderPage title="Matrix" />} />
        <Route path="techniques" element={<PlaceholderPage title="Techniques" />} />
        <Route path="techniques/:attackId" element={<PlaceholderPage title="Technique Detail" />} />
        <Route path="groups" element={<PlaceholderPage title="Groups" />} />
        <Route path="groups/:attackId" element={<PlaceholderPage title="Group Detail" />} />
        <Route path="campaigns" element={<PlaceholderPage title="Campaigns" />} />
        <Route path="campaigns/:attackId" element={<PlaceholderPage title="Campaign Detail" />} />
        <Route path="software" element={<PlaceholderPage title="Software" />} />
        <Route path="software/:attackId" element={<PlaceholderPage title="Software Detail" />} />
        <Route path="data-sources" element={<PlaceholderPage title="Data Sources" />} />
        <Route path="data-sources/:attackId" element={<PlaceholderPage title="Data Source Detail" />} />
        <Route path="mitigations" element={<PlaceholderPage title="Mitigations" />} />
        <Route path="mitigations/:attackId" element={<PlaceholderPage title="Mitigation Detail" />} />
        <Route path="tactics" element={<PlaceholderPage title="Tactics" />} />
        <Route path="tactics/:attackId" element={<PlaceholderPage title="Tactic Detail" />} />
        <Route path="sectors" element={<PlaceholderPage title="Sectors" />} />
        <Route path="relationships" element={<PlaceholderPage title="Relationships" />} />
        <Route path="search" element={<PlaceholderPage title="Search Results" />} />
        <Route path="cti/reports" element={<PlaceholderPage title="Reports" />} />
        <Route path="cti/iocs" element={<PlaceholderPage title="IOCs" />} />
        <Route path="cti/sigma" element={<PlaceholderPage title="Sigma" />} />
        <Route path="cti/feed-status" element={<PlaceholderPage title="Feed Status" />} />
        <Route path="*" element={<PlaceholderPage title="404 - Not Found" />} />
      </Route>
    </Routes>
  );
}
