import type { Metadata } from 'next';
import { OwaspAiReference } from '../../../src/views/OwaspAiReference';

export const metadata: Metadata = {
  title: 'OWASP AI Exchange — MITRE Explorer',
  description:
    'Reference page for the OWASP AI Exchange — AI/ML threats, controls, and framework alignments (ISO 27090, EU AI Act, MITRE ATLAS roadmap).',
};

export default function Page() {
  return <OwaspAiReference />;
}
