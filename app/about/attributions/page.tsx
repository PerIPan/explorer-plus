import type { Metadata } from 'next';
import { Attributions } from '../../../src/views/Attributions';

export const metadata: Metadata = {
  title: 'Data attributions — MITRE Explorer Plus',
  description: 'Licensing + upstream sources for every external data feed ingested into MITRE Explorer Plus.',
};

export default function Page() {
  return <Attributions />;
}
