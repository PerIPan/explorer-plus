import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { AtomicTests } from '../../../src/views/AtomicTests';

export const metadata: Metadata = {
  title: 'Atomic Tests',
  description:
    'Red team validation tests from Atomic Red Team',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading atomic tests..." />}>
      <AtomicTests />
    </Suspense>
  );
}
