import { Suspense } from 'react';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { GhsaDetail } from '../../../../src/views/GhsaDetail';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading advisory..." />}>
      <GhsaDetail />
    </Suspense>
  );
}
