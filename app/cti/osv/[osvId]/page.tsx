import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { OsvDetail } from '../../../../src/views/OsvDetail';

export const metadata: Metadata = {
  title: 'OSV advisory — MITRE Explorer',
  description:
    'Open Source Vulnerability advisory detail — OS, distro, and kernel records from OSV.dev',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading OSV advisory..." />}>
      <OsvDetail />
    </Suspense>
  );
}
