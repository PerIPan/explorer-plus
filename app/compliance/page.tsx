import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ComplianceHub } from '../../src/views/ComplianceHub';

export const metadata: Metadata = {
  title: 'Compliance — MITRE Explorer',
  description:
    'Regulatory and audit frameworks bridged to MITRE ATT&CK via the Secure Controls Framework (SCF). NIS2, DORA, PCI DSS, NIST 800-53, HIPAA, GDPR, CMMC and more — mapped to the techniques they help mitigate.',
  openGraph: {
    title: 'Compliance — MITRE Explorer',
    description:
      'Compliance frameworks bridged to MITRE ATT&CK. NIS2, DORA, PCI DSS, NIST 800-53, HIPAA, GDPR, CMMC — mapped to techniques.',
    url: 'https://mitre-explorer.org/compliance',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading frameworks..." />}>
      <ComplianceHub />
    </Suspense>
  );
}
