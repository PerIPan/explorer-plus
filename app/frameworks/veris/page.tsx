import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { VerisCategories } from '../../../src/views/VerisCategories';

export const metadata: Metadata = {
  title: 'VERIS Categories',
  description:
    'Verizon DBIR incident classification mapped to ATT&CK techniques',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading VERIS categories..." />}>
      <VerisCategories />
    </Suspense>
  );
}
