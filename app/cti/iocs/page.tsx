import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { IocsList } from '../../../src/views/IocsList';

export const metadata: Metadata = {
  title: 'IOC Indicators',
  description:
    'Hashes, domains, IPs from OTX, ThreatFox, and MalwareBazaar',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading IOCs..." />}>
      <IocsList />
    </Suspense>
  );
}
