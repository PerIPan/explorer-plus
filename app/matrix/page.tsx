import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { Matrix } from '../../src/views/Matrix';

export const metadata: Metadata = {
  title: 'ATT&CK Matrix',
  description:
    'Interactive technique heatmap across tactics',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading matrix..." />}>
      <Matrix />
    </Suspense>
  );
}
