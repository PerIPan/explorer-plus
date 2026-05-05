import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../src/components/shared/FoldingDiamond';

export const metadata: Metadata = {
  title: 'MITRE Explorer Plus — ATT&CK v19, CVEs, CTI',
  description: 'MITRE ATT&CK v19 + ATLAS — CTI reports, CVEs, applications, OSS packages, and threat-actor relationships across enterprise, mobile, ICS, and AI/ML.',
};

import { Relationships } from '../src/views/Relationships';

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <Relationships />
    </Suspense>
  );
}
