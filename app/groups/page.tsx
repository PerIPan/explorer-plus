import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { GroupsList } from '../../src/pages/GroupsList';

export const metadata: Metadata = {
  title: 'Threat Groups',
  description:
    '191 tracked adversary groups (APT29, Lazarus, FIN7, etc.) with techniques, software, campaigns, and targeted sectors',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading groups..." />}>
      <GroupsList />
    </Suspense>
  );
}
