import './globals.css';
import { headers } from 'next/headers';
import type { Metadata } from 'next';
import { Providers } from './providers';
import { SITE_URL } from '../src/lib/site';

const THEME_SCRIPT = `(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme:dark)').matches)) {
      document.documentElement.classList.add('dark');
    }
  } catch(e) {}
})();`;

const SITE_DESC =
  'Multi-domain threat intelligence platform built on MITRE ATT&CK — bridging techniques, threat groups, malware and campaigns to CVEs, advisories, detections and compliance frameworks.';

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: 'MITRE Explorer', template: '%s — MITRE Explorer' },
  description: SITE_DESC,
  openGraph: {
    type: 'website',
    siteName: 'MITRE Explorer',
    url: SITE_URL,
    title: 'MITRE Explorer',
    description: SITE_DESC,
  },
  twitter: { card: 'summary', title: 'MITRE Explorer', description: SITE_DESC },
};

// Site-identity structured data for search + AI answer engines (GEO).
const SITE_JSONLD = {
  '@context': 'https://schema.org',
  '@graph': [
    {
      '@type': 'WebSite',
      '@id': `${SITE_URL}/#website`,
      url: SITE_URL,
      name: 'MITRE Explorer',
      description: SITE_DESC,
    },
    {
      '@type': 'Organization',
      '@id': `${SITE_URL}/#org`,
      name: 'MITRE Explorer',
      url: SITE_URL,
      description:
        'Independent threat-intelligence knowledge base. Not affiliated with or endorsed by MITRE.',
    },
  ],
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') ?? '';

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/diamond-favicon.svg" type="image/svg+xml" />
        <script nonce={nonce} suppressHydrationWarning dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
        <script
          type="application/ld+json"
          nonce={nonce}
          dangerouslySetInnerHTML={{ __html: JSON.stringify(SITE_JSONLD) }}
        />
      </head>
      <body className="bg-[var(--surface-deep)] text-[var(--text-primary)]">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
