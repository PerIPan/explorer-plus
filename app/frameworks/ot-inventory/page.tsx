import type { Metadata } from 'next';
import { OtInventoryGuide } from '../../../src/views/OtInventoryGuide';

export const metadata: Metadata = {
  title: 'OT Asset Inventory (CISA) — MITRE Explorer',
  description:
    'CISA’s multinational OT asset-inventory guidance (August 2025): the five steps, the 32 inventory fields by ' +
    'priority, and the oil & gas, electricity and water taxonomies — each row mapped (by this project) to the ' +
    'ATT&CK for ICS assets, with rows ATT&CK does not model shown as such.',
  alternates: { canonical: '/frameworks/ot-inventory' },
};

export default function Page() {
  return <OtInventoryGuide />;
}
