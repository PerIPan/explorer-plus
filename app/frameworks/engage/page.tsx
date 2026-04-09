import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { EngageActivities } from '../../../src/views/EngageActivities';

export const metadata: Metadata = {
  title: 'MITRE Engage',
  description:
    'Adversary engagement activities mapped per ATT&CK technique',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading Engage activities..." />}>
      <EngageActivities />
    </Suspense>
  );
}
