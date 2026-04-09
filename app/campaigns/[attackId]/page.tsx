import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchCampaign } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { CampaignDetail } from '../../../src/views/CampaignDetail';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchCampaign(attackId);
  if (!data) return { title: 'Not Found' };
  const title = `${data.attack_id} ${data.name}`;
  const description = data.description?.slice(0, 160) ?? `Details for ${data.attack_id} ${data.name}`;
  return {
    title,
    description,
    openGraph: { title, description, url: `https://mitre-explorer.org/campaigns/${data.attack_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchCampaign(attackId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <CampaignDetail />
    </Suspense>
  );
}
