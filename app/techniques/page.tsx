import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { TechniquesList } from '../../src/pages/TechniquesList';

export const metadata: Metadata = {
  title: 'ATT&CK Techniques',
  description:
    'Browse 800+ adversary techniques and sub-techniques across Enterprise, Mobile, ICS, and ATLAS domains with linked threat groups, software, and detection strategies',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading techniques..." />}>
      <TechniquesList />
    </Suspense>
  );
}
