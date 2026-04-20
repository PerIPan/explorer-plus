import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { AdvisoriesList } from '../../../src/views/AdvisoriesList';

export const metadata: Metadata = {
  title: 'Advisories — MITRE Explorer',
  description:
    'Unified GHSA + OSV advisories — OSS package vulnerabilities and OS/distro/kernel advisories in one list with faceted filters',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading advisories..." />}>
      <AdvisoriesList />
    </Suspense>
  );
}
