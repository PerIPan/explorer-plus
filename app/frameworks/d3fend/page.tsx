import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { D3fendFramework } from '../../../src/views/D3fendFramework';

export const metadata: Metadata = {
  title: 'MITRE D3FEND',
  description:
    'MITRE D3FEND defensive countermeasures mapped to the ATT&CK techniques they counter. Browse the Model, Harden, Detect, Isolate, Deceive, Evict and Restore tactics across Enterprise and ICS.',
  openGraph: {
    title: 'MITRE D3FEND — MITRE Explorer',
    description:
      'Defensive countermeasures mapped to the ATT&CK techniques they counter, across Enterprise and ICS.',
    url: 'https://mitre-explorer.org/frameworks/d3fend',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading D3FEND..." />}>
      <D3fendFramework />
    </Suspense>
  );
}
