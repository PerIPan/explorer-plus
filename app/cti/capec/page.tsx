import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CapecList } from '../../../src/views/CapecList';

export const metadata: Metadata = {
  title: 'CAPEC Attack Patterns',
  description:
    'MITRE Common Attack Pattern Enumeration and Classification — 615 patterns with severity, likelihood, prerequisites, consequences, and mitigations.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading CAPEC patterns..." />}>
      <CapecList />
    </Suspense>
  );
}
