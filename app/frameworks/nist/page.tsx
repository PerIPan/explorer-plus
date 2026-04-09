import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { NistControls } from '../../../src/views/NistControls';

export const metadata: Metadata = {
  title: 'NIST 800-53 Controls',
  description:
    'Federal security controls mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading NIST controls..." />}>
      <NistControls />
    </Suspense>
  );
}
