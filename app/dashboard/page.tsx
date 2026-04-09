import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';

export const metadata: Metadata = {
  title: 'Overview',
  description: 'Summary statistics, top threat groups, technique distribution, and sector breakdown across the ATT&CK knowledge base',
};

// Dynamic import to avoid issues — Dashboard is a client component
import { Dashboard as DashboardClient } from '../../src/views/Dashboard';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading dashboard..." />}>
      <DashboardClient />
    </Suspense>
  );
}
