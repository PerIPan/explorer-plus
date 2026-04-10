import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CsfFramework } from '../../../src/views/CsfFramework';

export const metadata: Metadata = {
  title: 'NIST CSF v2',
  description:
    'NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques. Browse Govern, Identify, Protect, Detect, Respond, and Recover functions.',
  openGraph: {
    title: 'NIST CSF v2 — MITRE Explorer',
    description:
      'NIST Cybersecurity Framework v2 subcategories mapped to ATT&CK techniques.',
    url: 'https://mitre-explorer.org/frameworks/csf',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading CSF..." />}>
      <CsfFramework />
    </Suspense>
  );
}
