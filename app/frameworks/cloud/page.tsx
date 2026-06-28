import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CloudControls } from '../../../src/views/CloudControls';

export const metadata: Metadata = {
  title: 'Cloud Controls',
  description:
    'AWS, Azure, and GCP security controls mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading cloud controls..." />}>
      <CloudControls />
    </Suspense>
  );
}
