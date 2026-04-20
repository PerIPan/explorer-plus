import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { CapecDetail } from '../../../../src/views/CapecDetail';

export const metadata: Metadata = {
  title: 'CAPEC Pattern',
  description: 'MITRE Common Attack Pattern Enumeration and Classification detail.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading CAPEC pattern..." />}>
      <CapecDetail />
    </Suspense>
  );
}
