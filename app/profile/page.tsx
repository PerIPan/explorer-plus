import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ThreatProfile } from '../../src/views/ThreatProfile';
import { OtProfile } from '../../src/views/OtProfile';

/**
 * Branches on the same `domain` param the render branch below uses. A static
 * export here described the IT briefing only, which stopped being true the
 * moment this route started serving both engines — an OT visitor's shared link
 * previewed as a sector briefing they never saw.
 */
/** The one domain that routes to the OT engine. Mirrors the branch in
 * app/api/v1/profile/route.ts, which switches on `domain=ics-attack` alone. */
const OT_DOMAIN = 'ics-attack';

export async function generateMetadata({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}): Promise<Metadata> {
  const raw = (await searchParams).domain;
  const domain = Array.isArray(raw) ? raw[0] : raw;

  if (domain === OT_DOMAIN) {
    return {
      title: 'Threat Profile — OT plant',
      description:
        'ATT&CK for ICS techniques ranked for one plant: exposure across your asset surface, and lift over how far each technique reaches across all ATT&CK ICS assets.',
    };
  }
  return {
    title: 'Threat Profile',
    description:
      'Techniques ranked for one sector: reach by CTI evidence, and sector fit by lift over the threat groups attributed to that sector.',
  };
}

/**
 * Two briefings live at this one route because they answer the same question
 * from incompatible inputs: the IT engine ranks Enterprise techniques for a
 * SECTOR, the OT engine ranks ICS techniques for an ASSET selection. ICS has no
 * usable platform vocabulary and no Sigma/IOC/report/KEV/EPSS evidence at all,
 * so it cannot be served as a filtered variant of the IT view — it needs
 * different questions and different columns.
 *
 * The branch is made here, on the server, rather than inside a shared client
 * component: whichever view loses the branch is then never sent to the browser.
 *
 * Both views read the rest of their input from `useSearchParams`, which forces
 * every ancestor into client-side rendering unless it sits under a Suspense
 * boundary — without one, `next build` fails the route outright. Same shape as
 * app/page.tsx; the fallback is the app's own loader rather than `null` so a
 * slow first paint does not read as an empty briefing.
 */
export default async function Page({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const params = await searchParams;
  const raw = params.domain;
  const domain = Array.isArray(raw) ? raw[0] : raw;
  const isOt = domain === OT_DOMAIN;

  return (
    <Suspense fallback={<DiamondLoader text="Loading threat profile..." />}>
      {isOt ? <OtProfile /> : <ThreatProfile />}
    </Suspense>
  );
}
