import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { SectorsList } from '../../src/views/SectorsList';

export const metadata: Metadata = {
  title: 'Industry Sectors',
  description:
    'Threat landscape by industry',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading sectors..." />}>
      <SectorsList />
    </Suspense>
  );
}
