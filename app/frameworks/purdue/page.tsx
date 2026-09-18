import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { PurdueModel } from '../../../src/views/PurdueModel';

export const metadata: Metadata = {
  title: 'Purdue Model',
  description:
    'The Purdue model for OT networks — seven levels from the physical process to enterprise IT, which ATT&CK for ICS assets sit at each, and which levels may communicate.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading Purdue model..." />}>
      <PurdueModel />
    </Suspense>
  );
}
