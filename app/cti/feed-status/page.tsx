import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { FeedStatus } from '../../../src/views/FeedStatus';

export const metadata: Metadata = {
  title: 'Feed Status',
  description:
    'CTI pipeline health',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading feed status..." />}>
      <FeedStatus />
    </Suspense>
  );
}
