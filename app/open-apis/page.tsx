import type { Metadata } from 'next';
import { OpenApis } from '../../src/views/OpenApis';
import { API_CATALOG } from '../../src/lib/api-catalog';

export const metadata: Metadata = {
  title: 'Open APIs — free threat-intel REST API, no key',
  description:
    `A public JSON API over MITRE ATT&CK, CVEs, EPSS, KEV, GHSA/OSV advisories, CAPEC, compliance frameworks and ICS assets. ` +
    `${API_CATALOG.length} documented endpoints, no key, no sign-up, no rate limit, open CORS — with a live response for each one.`,
  alternates: { canonical: '/open-apis' },
};

export default function Page() {
  return <OpenApis />;
}
