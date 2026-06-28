import { notFound } from 'next/navigation';
import { headers } from 'next/headers';
import { Suspense } from 'react';
import { fetchTechnique } from '../../lib/data';
import { DiamondLoader } from '../../../src/components/shared/FoldingDiamond';
import { TechniqueDetail } from '../../../src/views/TechniqueDetail';

// Canonical upstream URL for entity disambiguation (sameAs). ATLAS (AML.*)
// techniques live on atlas.mitre.org; Enterprise sub-techniques use a slashed
// path (T1059.001 -> /techniques/T1059/001).
function upstreamTechniqueUrl(attackId: string): string {
  if (attackId.startsWith('AML.')) return `https://atlas.mitre.org/techniques/${attackId}`;
  return `https://attack.mitre.org/techniques/${attackId.replace('.', '/')}`;
}

export async function generateMetadata({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);
  if (!data) return { title: 'Not Found' };
  const title = `${data.attack_id} ${data.name}`;
  const description = data.description?.slice(0, 160) ?? `Details for ${data.attack_id} ${data.name}`;
  return {
    title,
    description,
    openGraph: { title, description, url: `https://mitre-explorer.org/techniques/${data.attack_id}` },
  };
}

export const revalidate = 3600;

export default async function Page({ params }: { params: Promise<{ attackId: string }> }) {
  const { attackId } = await params;
  const data = await fetchTechnique(attackId);
  if (!data) notFound();

  // GEO: structured data + sameAs disambiguation so AI/search engines can map
  // this page to the canonical technique and extract our cross-domain data.
  // nonce is required by the CSP; this page is already dynamically rendered
  // (root layout reads the nonce), so there's no caching penalty.
  const nonce = (await headers()).get('x-nonce') ?? '';
  const url = `https://mitre-explorer.org/techniques/${data.attack_id}`;
  const sameAs = upstreamTechniqueUrl(data.attack_id);
  const jsonLd = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    '@id': `${url}#technique`,
    url,
    name: `${data.attack_id} ${data.name}`,
    headline: `${data.attack_id} ${data.name}`,
    description: data.description?.slice(0, 300) ?? `MITRE ATT&CK technique ${data.attack_id} — ${data.name}`,
    isPartOf: { '@type': 'WebSite', '@id': 'https://mitre-explorer.org/#website' },
    about: {
      '@type': 'DefinedTerm',
      name: `${data.attack_id} ${data.name}`,
      termCode: data.attack_id,
      inDefinedTermSet: data.attack_id.startsWith('AML.') ? 'https://atlas.mitre.org' : 'https://attack.mitre.org',
      sameAs,
    },
    sameAs,
  };

  return (
    <>
      <script
        type="application/ld+json"
        nonce={nonce}
        dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
      />
      <Suspense fallback={<DiamondLoader text="Loading..." />}>
        <TechniqueDetail />
      </Suspense>
    </>
  );
}
