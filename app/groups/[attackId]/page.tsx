import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchGroup } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { GroupDetail } from '../../../src/views/GroupDetail';

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchGroup(attackId);
  if (!data) return { title: 'Not Found' };
  const title = `${data.attack_id} ${data.name}`;
  const description = data.description?.slice(0, 160) ?? `Details for ${data.attack_id} ${data.name}`;
  return {
    title,
    description,
    openGraph: { title, description, url: `https://mitre-explorer.org/groups/${data.attack_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchGroup(attackId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <GroupDetail />
    </Suspense>
  );
}
