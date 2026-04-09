import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { Search } from '../../src/views/Search';

export const metadata: Metadata = {
  title: 'Search',
  description:
    'Search across techniques, groups, software, campaigns, CVEs, and OWASP categories',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Searching..." />}>
      <Search />
    </Suspense>
  );
}
