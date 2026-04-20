import type { Metadata } from 'next';
import { CraReference } from '../../../src/views/CraReference';

export const metadata: Metadata = {
  title: 'EU Cyber Resilience Act (CRA) — MITRE Explorer',
  description:
    'Regulation (EU) 2024/2847 — essential cybersecurity requirements, Article 14 reporting cadence, and product categories for products with digital elements.',
};

export default function Page() {
  return <CraReference />;
}
