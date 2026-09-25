import type { Metadata } from 'next';
import { Suspense } from 'react';
import { DiamondLoader } from '../../src/components/shared/FoldingDiamond';
import { ThreatProfile } from '../../src/views/ThreatProfile';

export const metadata: Metadata = {
  title: 'Threat Profile',
  description:
    'Techniques ranked for one sector: reach by CTI evidence, and sector fit by lift over the threat groups attributed to that sector.',
};

/**
 * `ThreatProfile` reads its whole input from `useSearchParams`, which forces
 * every ancestor into client-side rendering unless it sits under a Suspense
 * boundary — without one, `next build` fails the route outright. Same shape as
 * app/page.tsx; the fallback is the app's own loader rather than `null` so a
 * slow first paint does not read as an empty briefing.
 */
export default function Page() {
  return (
    <Suspense fallback={<DiamondLoader text="Loading threat profile..." />}>
      <ThreatProfile />
    </Suspense>
  );
}
