import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { ReportsList } from '../../../src/views/ReportsList';

export const metadata: Metadata = {
  title: 'Threat Reports',
  description:
    'Live threat intelligence from AlienVault OTX and RSS feeds',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading reports..." />}>
      <ReportsList />
    </Suspense>
  );
}
