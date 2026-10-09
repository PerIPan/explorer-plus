import type { Metadata } from 'next';
import { FairCamReference } from '../../../src/views/FairCamReference';

export const metadata: Metadata = {
  title: 'FAIR-CAM — FAIR Controls Analytics Model — MITRE Explorer',
  description:
    'The FAIR Controls Analytics Model (FAIR-CAM™) v1.0 — loss event, variance management and decision support ' +
    'functions, quoted with their units and relationships (©2025 FAIR Institute, CC BY-NC-ND 4.0) — and this site’s ' +
    'classification of D3FEND countermeasures and ATT&CK mitigations into those functions.',
  alternates: { canonical: '/frameworks/fair-cam' },
};

export default function Page() {
  return <FairCamReference />;
}
