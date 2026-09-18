import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { AssetsList } from '../../src/views/AssetsList';

export const metadata: Metadata = {
  title: 'ICS Assets',
  description:
    'ATT&CK for ICS assets — PLCs, RTUs, HMIs, historians, gateways and safety controllers — with the techniques that target each and their place in the Purdue model.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading ICS assets..." />}>
      <AssetsList />
    </Suspense>
  );
}
