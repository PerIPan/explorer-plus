import './globals.css';
import { headers } from 'next/headers';
import type { Metadata } from 'next';

const THEME_SCRIPT = `(function(){
  try {
    var t = localStorage.getItem('theme');
    if (t === 'dark' || (!t && window.matchMedia('(prefers-color-scheme:dark)').matches)) {
      document.documentElement.classList.add('dark');
    }
  } catch(e) {}
})();`;

export const metadata: Metadata = {
  title: { default: 'MITRE Explorer', template: '%s — MITRE Explorer' },
  description: 'Multi-domain threat intelligence platform built on MITRE ATT&CK',
};

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const headersList = await headers();
  const nonce = headersList.get('x-nonce') ?? '';

  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="icon" href="/diamond-favicon.svg" type="image/svg+xml" />
        <script nonce={nonce} dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="bg-[var(--surface-deep)] text-[var(--text-primary)]">
        {children}
      </body>
    </html>
  );
}
