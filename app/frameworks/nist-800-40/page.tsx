import type { Metadata } from 'next';
import { Nist80040Reference } from '../../../src/views/Nist80040Reference';

export const metadata: Metadata = {
  title: 'NIST SP 800-40 Rev. 4 — Enterprise Patch Management Planning',
  description:
    'NIST SP 800-40r4: risk responses, the four patching scenarios, maintenance groups and plans, metrics and ' +
    'procurement questions — bridged to ATT&CK only through the eight SP 800-53 controls NIST itself names, ' +
    'via CTID’s control mappings.',
  alternates: { canonical: '/frameworks/nist-800-40' },
};

export default function Page() {
  return <Nist80040Reference />;
}
