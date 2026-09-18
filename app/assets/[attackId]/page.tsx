import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { AssetDetail } from '../../../src/views/AssetDetail';

export async function generateMetadata(
  { params }: { params: Promise<{ attackId: string }> },
): Promise<Metadata> {
  const { attackId } = await params;
  const id = attackId.toUpperCase();
  return {
    title: `${id} — ICS Asset`,
    description: `ATT&CK for ICS asset ${id}: techniques that target it, its Purdue level, and related equipment.`,
  };
}

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  return (
    <Suspense fallback={<DiamondLoader text="Loading asset..." />}>
      <AssetDetail attackId={attackId.toUpperCase()} />
    </Suspense>
  );
}
