import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { DetectionStrategies } from '../../../src/views/DetectionStrategies';

export const metadata: Metadata = {
  title: 'Detection Strategies',
  description:
    'ATT&CK v18 detection strategies and analytics',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading detection strategies..." />}>
      <DetectionStrategies />
    </Suspense>
  );
}
