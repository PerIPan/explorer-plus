import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { SigmaList } from '../../../src/views/SigmaList';

export const metadata: Metadata = {
  title: 'Sigma Rules',
  description:
    '3,100+ detection signatures from SigmaHQ',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading Sigma rules..." />}>
      <SigmaList />
    </Suspense>
  );
}
