import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { CampaignsList } from '../../src/views/CampaignsList';

export const metadata: Metadata = {
  title: 'Campaigns',
  description:
    'Named intrusion operations with timelines, attributed groups, techniques, and software',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading campaigns..." />}>
      <CampaignsList />
    </Suspense>
  );
}
