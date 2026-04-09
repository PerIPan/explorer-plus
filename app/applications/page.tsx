import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ApplicationsList } from '../../src/views/ApplicationsList';

export const metadata: Metadata = {
  title: 'Applications',
  description:
    '7,000+ vendor products linked to CVEs, CWEs, and ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading applications..." />}>
      <ApplicationsList />
    </Suspense>
  );
}
