import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { EmulationPlans } from '../../../src/views/EmulationPlans';

export const metadata: Metadata = {
  title: 'Adversary Emulation Plans',
  description:
    'MITRE CTID adversary emulation plans for APT29, Carbanak, FIN6, FIN7, menuPass, OilRig, Sandworm, Turla and ' +
    'Wizard Spider — every step resolved to its current ATT&CK technique, with how much of each group’s ' +
    'attributed techniques the plan exercises.',
  alternates: { canonical: '/frameworks/emulation' },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading emulation plans..." />}>
      <EmulationPlans />
    </Suspense>
  );
}
