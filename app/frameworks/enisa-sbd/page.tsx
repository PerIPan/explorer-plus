import type { Metadata } from 'next';
import { EnisaPlaybooks } from '../../../src/views/EnisaPlaybooks';
import { ENISA_SBD_COUNT } from '../../../src/lib/enisa-sbd';

export const metadata: Metadata = {
  title: 'ENISA Playbooks — Secure by Design and Default — MITRE Explorer',
  description:
    `ENISA's ${ENISA_SBD_COUNT} Secure by Design and Secure by Default playbooks for SMEs: principle, ` +
    'objective, checklist, minimum evidence and release gate for each. Reference list — the source ' +
    'carries no ATT&CK, CWE or control identifiers, so no crosswalk is shown.',
  alternates: { canonical: '/frameworks/enisa-sbd' },
};

export default function Page() {
  return <EnisaPlaybooks />;
}
