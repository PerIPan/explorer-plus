import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../src/components/shared/FoldingDiamond';

export const metadata: Metadata = {
  title: '360 Views — MITRE Explorer',
  description: 'Search any entity and explore its relationships — technique maps, actor profiles, application maps, and force-directed graphs',
};

import { Relationships } from '../src/views/Relationships';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <Relationships />
    </Suspense>
  );
}
