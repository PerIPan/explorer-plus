import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchCve } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { CveDetail } from '../../../../src/views/CveDetail';

export async function generateMetadata({ params }: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await params;
  const data = await fetchCve(cveId);
  if (!data) return { title: 'Not Found' };
  const description = data.description?.slice(0, 160) ?? `Details for ${data.cve_id}`;
  return {
    title: data.cve_id,
    description,
    openGraph: { title: data.cve_id, description, url: `https://mitre-explorer.org/cti/cves/${data.cve_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await params;
  const data = await fetchCve(cveId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <CveDetail />
    </Suspense>
  );
}
