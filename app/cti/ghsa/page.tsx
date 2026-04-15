import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { GhsaList } from '../../../src/views/GhsaList';

export const metadata: Metadata = {
  title: 'GitHub Security Advisories',
  description:
    'Library-level vulnerabilities for npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust — mapped to ATT&CK via CWE→CAPEC bridge.',
  openGraph: {
    title: 'GitHub Security Advisories — MITRE Explorer',
    description: 'Library-level vulnerabilities mapped to ATT&CK techniques.',
    url: 'https://mitre-explorer.org/cti/ghsa',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading GHSA advisories..." />}>
      <GhsaList />
    </Suspense>
  );
}
