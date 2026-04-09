import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { OwaspTop10 } from '../../../src/views/OwaspTop10';

export const metadata: Metadata = {
  title: 'OWASP Top 10',
  description:
    'Web, ML, LLM security risks mapped to ATT&CK and ATLAS techniques via CWE',
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading OWASP..." />}>
      <OwaspTop10 />
    </Suspense>
  );
}
