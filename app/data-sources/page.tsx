import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { DataSourcesList } from '../../src/views/DataSourcesList';

export const metadata: Metadata = {
  title: 'Data Sources',
  description:
    'Telemetry sources for detecting ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading data sources..." />}>
      <DataSourcesList />
    </Suspense>
  );
}
