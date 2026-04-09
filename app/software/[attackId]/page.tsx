import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchSoftware } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { SoftwareDetail } from '../../../src/views/SoftwareDetail';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchSoftware(attackId);
  if (!data) return { title: 'Not Found' };
  return {
    title: `${data.attack_id} ${data.name}`,
    description: data.description?.slice(0, 160) ?? `Details for ${data.attack_id} ${data.name}`,
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchSoftware(attackId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <SoftwareDetail />
    </Suspense>
  );
}
