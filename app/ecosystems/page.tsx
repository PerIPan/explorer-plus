import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { EcosystemsList } from '../../src/views/EcosystemsList';

export const metadata: Metadata = {
  title: 'Ecosystems — MITRE Explorer',
  description:
    'OSS package registries (npm, PyPI, Maven, …) and OS/distro/kernel advisory catalogues (Linux, Debian, Ubuntu, Alpine, Android, …) — one dashboard per ecosystem with severity breakdown and top affected packages.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading ecosystems..." />}>
      <EcosystemsList />
    </Suspense>
  );
}
