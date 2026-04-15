import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { PackagesList } from '../../src/views/PackagesList';

export const metadata: Metadata = {
  title: 'Packages',
  description:
    'Library and dependency packages with GitHub Security Advisories across npm, PyPI, Go, Maven, RubyGems, NuGet, Composer, Rust.',
  openGraph: {
    title: 'Packages — MITRE Explorer',
    description: 'Library-level vulnerability browse, parallel to Applications.',
    url: 'https://mitre-explorer.org/packages',
  },
};

export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading packages..." />}>
      <PackagesList />
    </Suspense>
  );
}
