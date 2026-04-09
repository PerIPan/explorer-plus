import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchOwaspCategory } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { OwaspTop10 } from '../../../../src/views/OwaspTop10';

export async function generateMetadata({ params }: { params: Promise<{ categoryId: string }> }) {
  const { categoryId } = await params;
  const data = await fetchOwaspCategory(categoryId);
  if (!data) return { title: 'Not Found' };
  const title = `${data.category_id} ${data.name}`;
  const description = data.description?.slice(0, 160) ?? `Details for ${data.category_id} ${data.name}`;
  return {
    title,
    description,
    openGraph: { title, description, url: `https://mitre-explorer.org/frameworks/owasp/${data.category_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ categoryId: string }> }) {
  const { categoryId } = await params;
  const data = await fetchOwaspCategory(categoryId);
  if (!data) notFound();
  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <OwaspTop10 />
    </Suspense>
  );
}
