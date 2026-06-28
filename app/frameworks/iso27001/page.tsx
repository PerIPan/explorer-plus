import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { Iso27001Framework } from '../../../src/views/Iso27001Framework';

export const metadata: Metadata = {
  title: 'ISO/IEC 27001:2022',
  description:
    'ISO/IEC 27001:2022 Annex A controls and mandatory clauses mapped to MITRE ATT&CK techniques via the NIST CSF v2 crosswalk.',
  openGraph: {
    title: 'ISO/IEC 27001:2022 — MITRE Explorer',
    description:
      'ISO/IEC 27001:2022 controls mapped to MITRE ATT&CK techniques via the NIST CSF v2 crosswalk.',
    url: 'https://mitre-explorer.org/frameworks/iso27001',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading ISO/IEC 27001:2022..." />}>
      <Iso27001Framework />
    </Suspense>
  );
}
