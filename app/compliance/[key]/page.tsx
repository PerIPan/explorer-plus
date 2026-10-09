import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { ComplianceFrameworkDetail } from '../../../src/views/ComplianceFrameworkDetail';
import { getFrameworkEntry } from '../../../src/lib/scf-framework-registry';
import { fetchComplianceFramework } from '../../lib/data';

interface RouteProps { params: Promise<{ key: string }> }

/** Framework keys are lower-case slugs ("eu-cra", "mitre-att_ck-16-1"); anything else is not one. */
const FRAMEWORK_KEY = /^[a-z0-9][a-z0-9_&.-]{0,99}$/;

/**
 * The framework to render, or null for not-found: an unknown key, or a Tier-3
 * key with no references. The hub already hides the latter — SCF re-keys and
 * retires documents (2026.3 left 34 such rows), and their pages rendered an
 * empty shell with a title made up from the slug ("NO SUCH KEY — Compliance").
 * Retired keys with a successor never get here: middleware 308s them
 * (src/lib/canonical-redirects.mjs). Curated Tier-1/2 keys always render: one
 * at zero is a signal to investigate, as eu-cra was.
 */
async function resolveFramework(key: string) {
  if (!FRAMEWORK_KEY.test(key)) return null;
  const row = await fetchComplianceFramework(key);
  if (!row) return null;
  if (row.tier >= 3 && row.scf_controls === 0) return null;
  return row;
}

export async function generateMetadata({ params }: RouteProps): Promise<Metadata> {
  const { key } = await params;
  const row = await resolveFramework(key);
  if (!row) return { title: 'Not Found' }; // the not-found page adds noindex itself
  const entry = getFrameworkEntry(key);
  const name = entry?.name ?? row.name;
  const blurb = entry?.short_blurb ?? row.short_blurb;
  return {
    title: `${name} — Compliance`,
    description: blurb
      ? `${blurb} Mapped to MITRE ATT&CK techniques via the Secure Controls Framework (SCF).`
      : `${name} mapped to MITRE ATT&CK techniques via the Secure Controls Framework (SCF).`,
    alternates: { canonical: `/compliance/${row.framework_key}` },
    openGraph: {
      title: `${name} — Compliance`,
      description: blurb ?? 'Compliance framework mapped to MITRE ATT&CK.',
      url: `https://mitre-explorer.org/compliance/${row.framework_key}`,
    },
  };
}

export default async function Page({ params }: RouteProps) {
  const { key } = await params;
  if (!(await resolveFramework(key))) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading framework..." />}>
      <ComplianceFrameworkDetail frameworkKey={key} />
    </Suspense>
  );
}
