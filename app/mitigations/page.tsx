import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { MitigationsList } from '../../src/views/MitigationsList';

export const metadata: Metadata = {
  title: 'Mitigations',
  description:
    'Security countermeasures mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading mitigations..." />}>
      <MitigationsList />
    </Suspense>
  );
}
