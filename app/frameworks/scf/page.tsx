import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { ScfFramework } from '../../../src/views/ScfFramework';

export const metadata: Metadata = {
  title: 'Secure Controls Framework (SCF)',
  description:
    'The 1,534-control catalogue that NIS2, DORA, PCI DSS, ISO 27001, HIPAA and 250 other frameworks are crosswalked through, with the ATT&CK techniques the mapped controls bridge to.',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading SCF controls..." />}>
      <ScfFramework />
    </Suspense>
  );
}
