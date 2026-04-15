import { Suspense } from 'react';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { PackageDetail } from '../../../../src/views/PackageDetail';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading package..." />}>
      <PackageDetail />
    </Suspense>
  );
}
