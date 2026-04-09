import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ExternalActors } from '../../src/views/ExternalActors';

export const metadata: Metadata = {
  title: 'Non-MITRE Actors',
  description:
    '500+ extended threat actors from ThaiCERT/ETDA',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading external actors..." />}>
      <ExternalActors />
    </Suspense>
  );
}
