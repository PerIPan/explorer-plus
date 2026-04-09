import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CvesList } from '../../../src/views/CvesList';

export const metadata: Metadata = {
  title: 'CVE Vulnerabilities',
  description:
    '21,000+ CVEs enriched with NVD scores, CISA KEV status',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading CVEs..." />}>
      <CvesList />
    </Suspense>
  );
}
