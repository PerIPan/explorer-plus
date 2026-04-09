import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchDataSource } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { DataSourceDetail } from '../../../src/views/DataSourceDetail';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchDataSource(attackId);
  if (!data) return { title: 'Not Found' };
  return {
    title: `${data.attack_id} ${data.name}`,
    description: data.description?.slice(0, 160) ?? `Details for ${data.attack_id} ${data.name}`,
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchDataSource(attackId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <DataSourceDetail />
    </Suspense>
  );
}
