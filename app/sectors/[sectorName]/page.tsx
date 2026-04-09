import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchSector } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { SectorDetail } from '../../../src/views/SectorDetail';

export async function generateMetadata({ params }: { params: Promise<{ sectorName: string }> }) {
  const { sectorName } = await params;
  const slug = decodeURIComponent(sectorName);
  const data = await fetchSector(slug);
  if (!data) return { title: 'Not Found' };
  return {
    title: data.name,
    description: `Threat groups targeting the ${data.name} sector with ATT&CK techniques and campaigns`,
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ sectorName: string }> }) {
  const { sectorName } = await params;
  const slug = decodeURIComponent(sectorName);
  const data = await fetchSector(slug);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <SectorDetail />
    </Suspense>
  );
}
