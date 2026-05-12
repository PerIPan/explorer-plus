import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { ComplianceFrameworkDetail } from '../../../src/views/ComplianceFrameworkDetail';
import { getFrameworkEntry } from '../../../src/lib/scf-framework-registry';

interface RouteProps { params: Promise<{ key: string }> }

export async function generateMetadata({ params }: RouteProps): Promise<Metadata> {
  const { key } = await params;
  const entry = getFrameworkEntry(key);
  const name = entry?.name ?? key.replaceAll('-', ' ').toUpperCase();
  return {
    title: `${name} — Compliance — MITRE Explorer`,
    description: entry?.short_blurb
      ? `${entry.short_blurb} Mapped to MITRE ATT&CK techniques via the Secure Controls Framework (SCF).`
      : `${name} compliance framework mapped to MITRE ATT&CK techniques via the Secure Controls Framework (SCF).`,
    openGraph: {
      title: `${name} — Compliance`,
      description: entry?.short_blurb ?? 'Compliance framework mapped to MITRE ATT&CK.',
      url: `https://mitre-explorer.org/compliance/${key}`,
    },
  };
}

export default async function Page({ params }: RouteProps) {
  const { key } = await params;
  return (
    <Suspense fallback={<DiamondLoader text="Loading framework..." />}>
      <ComplianceFrameworkDetail frameworkKey={key} />
    </Suspense>
  );
}
