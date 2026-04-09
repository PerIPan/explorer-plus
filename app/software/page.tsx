import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { SoftwareList } from '../../src/views/SoftwareList';

export const metadata: Metadata = {
  title: 'Attacker Software',
  description:
    'Malware and hacking tools used by threat actors mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading software..." />}>
      <SoftwareList />
    </Suspense>
  );
}
