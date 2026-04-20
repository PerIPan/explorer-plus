import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { EcosystemDetail } from '../../../src/views/EcosystemDetail';

export const metadata: Metadata = {
  title: 'Ecosystem — MITRE Explorer',
  description:
    'Per-ecosystem advisory dashboard: severity breakdown, top affected packages, recent advisories sorted by severity.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading ecosystem..." />}>
      <EcosystemDetail />
    </Suspense>
  );
}
