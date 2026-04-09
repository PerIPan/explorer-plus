import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { ReactActions } from '../../../src/views/ReactActions';

export const metadata: Metadata = {
  title: 'RE&CT Actions',
  description:
    'Incident response playbooks mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading RE&CT actions..." />}>
      <ReactActions />
    </Suspense>
  );
}
