import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { TacticsList } from '../../src/views/TacticsList';

export const metadata: Metadata = {
  title: 'Tactics',
  description:
    'Kill chain phases from Reconnaissance to Impact',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading tactics..." />}>
      <TacticsList />
    </Suspense>
  );
}
