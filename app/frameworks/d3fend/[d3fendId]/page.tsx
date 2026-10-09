import type { Metadata } from 'next';
import { notFound, permanentRedirect } from 'next/navigation';
import { Suspense } from 'react';
import { fetchD3fendCountermeasure } from '../../../lib/data';
import { DiamondLoader } from '../../../../src/components/shared/FoldingDiamond';
import { D3fendFramework } from '../../../../src/views/D3fendFramework';

/** D3FEND ids are "D3-" plus letters/digits (D3-AM, D3-PSEP, D3-ANCI); reject anything else before touching the DB. */
const D3FEND_ID = /^D3-[A-Z0-9-]{1,40}$/i;

export async function generateMetadata({
  params,
}: {
  params: Promise<{ d3fendId: string }>;
}): Promise<Metadata> {
  const { d3fendId } = await params;
  if (!D3FEND_ID.test(d3fendId)) return { title: 'Not Found' };
  const data = await fetchD3fendCountermeasure(d3fendId);
  if (!data) return { title: 'Not Found' };

  const title = `${data.d3fend_id} — ${data.name ?? 'D3FEND countermeasure'}`;
  const description = `MITRE D3FEND ${data.tactic ? `${data.tactic} ` : ''}countermeasure ${data.name ?? data.d3fend_id}, and the ATT&CK techniques it counters.`;

  return {
    title,
    description,
    alternates: { canonical: `/frameworks/d3fend/${data.d3fend_id}` },
    openGraph: {
      title: `${title} — MITRE Explorer`,
      description,
      url: `https://mitre-explorer.org/frameworks/d3fend/${data.d3fend_id}`,
    },
  };
}

export const revalidate = 3600;

/** Deep link to one countermeasure: the browser view opens with it expanded (it reads the id from the route). */
export default async function Page({
  params,
}: {
  params: Promise<{ d3fendId: string }>;
}) {
  const { d3fendId } = await params;
  if (!D3FEND_ID.test(d3fendId)) notFound();
  // One URL per countermeasure: /frameworks/d3fend/d3-am → /frameworks/d3fend/D3-AM.
  if (d3fendId !== d3fendId.toUpperCase()) permanentRedirect(`/frameworks/d3fend/${d3fendId.toUpperCase()}`);
  const data = await fetchD3fendCountermeasure(d3fendId);
  if (!data) notFound();

  return (
    <Suspense fallback={<DiamondLoader text="Loading D3FEND..." />}>
      <D3fendFramework />
    </Suspense>
  );
}
