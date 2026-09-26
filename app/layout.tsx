import './globals.css';
import { headers } from 'next/headers';
import type { Metadata } from 'next';
import { Providers } from './providers';
import { SITE_URL } from '../src/lib/site';

const THEME_SCRIPT = `(function(){
  try {
    var t = localStorage.getItem('mx-theme');
    // Light is the default — only dark when the user explicitly picked it.
    if (t === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.add('light');
    }
  } catch(e) {
    document.documentElement.classList.add('light');
  }
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
        {/* Theme only. There was a second pre-paint script here for the
            Threat Profile's dismissal flag, which set `data-profile-seen` on
            <html> — an attribute nothing ever read: no CSS rule, no component,
            no module. It ran on every page load of every route to set a
            variable nobody consumed. The flash it was meant to prevent cannot
            happen anyway: the panel is shown only by `peek.open`, and the only
            thing that opens it is `armPeek`, which re-reads
            localStorage['mx-profile'] SYNCHRONOUSLY before dispatching
            (src/components/profile/useProfileState.ts), so a returning
            dismisser never opens anything to flash. Removed rather than given
            a reader, because the honest options were "make it load-bearing" or
            "delete it", and the guarantee it duplicated is already structural.
            The theme is a different case and still needs its script: it
            decides a class the FIRST paint depends on. */}
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
