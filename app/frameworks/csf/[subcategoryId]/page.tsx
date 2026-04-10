import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import { Suspense } from 'react';
import { fetchCsfSubcategory } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { CsfFramework } from '../../../../src/views/CsfFramework';

export async function generateMetadata({
  params,
}: {
  params: Promise<{ subcategoryId: string }>;
}): Promise<Metadata> {
  const { subcategoryId } = await params;
  const data = await fetchCsfSubcategory(subcategoryId);
  if (!data) return { title: 'Not Found' };

  const title = `${data.subcategory_id} — ${data.name.slice(0, 80)}`;
  const description =
    (data.description ?? data.name).slice(0, 160) ||
    `NIST CSF v2 subcategory ${data.subcategory_id}`;

  return {
    title: `${title} — MITRE Explorer`,
    description,
    openGraph: {
      title,
      description,
      url: `https://mitre-explorer.org/frameworks/csf/${data.subcategory_id}`,
    },
  };
}

export const revalidate = 3600;

export default async function Page({
  params,
}: {
  params: Promise<{ subcategoryId: string }>;
}) {
  const { subcategoryId } = await params;
  const data = await fetchCsfSubcategory(subcategoryId);
  if (!data) notFound();

  return (
    <Suspense fallback={<DiamondLoader text="Loading..." />}>
      <CsfFramework />
    </Suspense>
  );
}
