import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchCve } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { CveDetail } from '../../../../src/pages/CveDetail';

export async function generateMetadata({ params }: { params: Promise<{ cveId: string }> }) {
  const { cveId } = await params;
  const data = await fetchCve(cveId);
  if (!data) return { title: 'Not Found' };
  return {
    title: data.cve_id,
    description: data.description?.slice(0, 160) ?? `Details for ${data.cve_id}`,
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
