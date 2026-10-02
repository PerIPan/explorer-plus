import type { Metadata } from 'next';
import { Cli } from '../../src/views/Cli';
import { API_CATALOG } from '../../src/lib/api-catalog';
import { CLI_COMMAND_NAME } from '../../src/lib/site';

export const metadata: Metadata = {
  title: `CLI — mitre-explorer.org from the command line`,
  description:
    `${CLI_COMMAND_NAME} is a read-only command-line client for the public threat-intel API behind ` +
    `mitre-explorer.org: ${API_CATALOG.length} commands over MITRE ATT&CK, CVEs, EPSS, KEV, GHSA/OSV ` +
    `advisories, CAPEC and compliance frameworks. No key, no account, zero runtime dependencies.`,
  alternates: { canonical: '/cli' },
};

export default function Page() {
  return <Cli />;
}
