/**
 * Ecosystem metadata registry — keyed by URL slug.
 *
 * The `/ecosystems` list and `/ecosystems/<slug>` detail pages render from
 * this registry + live DB aggregates. Aggregates come from:
 *   - `osv_advisories.ecosystem` (case-preserved: "Debian", "Linux", …)
 *   - `packages.ecosystem` (lowercased: "npm", "pypi", …)
 *
 * Adding an ecosystem: append an entry below, pick a category, set the
 * displayName + canonical (the DB-side exact string) + optional homepage.
 * Module-load validation (see bottom) fails the build on malformed entries.
 *
 * **Slug rule:** URL-safe, lowercase, non-alnum → single hyphen, no
 * leading/trailing hyphens. Must match /^[a-z0-9-]{1,64}$/.
 *
 * **Drift:** the FeedStatus page's "Ecosystem registry coverage" row
 * compares registry entries to `SELECT DISTINCT ecosystem FROM
 * osv_advisories`. Missing entries surface as a yellow dot + list.
 */

export type EcosystemCategory =
  | 'package-manager'
  | 'os-distro'
  | 'container-distro'
  | 'kernel-misc';

export interface EcosystemMeta {
  /** URL-safe slug, lowercase + hyphens. /^[a-z0-9-]{1,64}$/ */
  slug: string;
  /** Human-readable display name, max 80 chars. */
  displayName: string;
  /** Exact string as stored in the DB (osv_advisories.ecosystem OR
   *  packages.ecosystem). Preserves original case. */
  canonical: string;
  /** Coarse category — drives the grouped-grid sections on /ecosystems. */
  category: EcosystemCategory;
  /** Optional upstream URL — HTTPS/HTTP only, validated at module load. */
  homepage?: string;
  /** One-line explainer, max 300 chars. */
  description: string;
}

// ── Registry ─────────────────────────────────────────────────────────────────
// Ordered within each category roughly by maturity / user familiarity.

const REGISTRY: EcosystemMeta[] = [
  // ── Package managers (GHSA-backed) ─────────────────────────────────────────
  { slug: 'npm', displayName: 'npm', canonical: 'npm', category: 'package-manager',
    homepage: 'https://www.npmjs.com/', description: 'JavaScript package registry' },
  { slug: 'pypi', displayName: 'PyPI', canonical: 'pypi', category: 'package-manager',
    homepage: 'https://pypi.org/', description: 'Python Package Index' },
  { slug: 'maven', displayName: 'Maven Central', canonical: 'maven', category: 'package-manager',
    homepage: 'https://central.sonatype.com/', description: 'Java / JVM package registry' },
  { slug: 'go', displayName: 'Go modules', canonical: 'go', category: 'package-manager',
    homepage: 'https://pkg.go.dev/', description: 'Go module registry (proxy.golang.org)' },
  { slug: 'nuget', displayName: 'NuGet', canonical: 'nuget', category: 'package-manager',
    homepage: 'https://www.nuget.org/', description: '.NET package registry' },
  { slug: 'rubygems', displayName: 'RubyGems', canonical: 'rubygems', category: 'package-manager',
    homepage: 'https://rubygems.org/', description: 'Ruby gem registry' },
  { slug: 'composer', displayName: 'Composer (Packagist)', canonical: 'composer', category: 'package-manager',
    homepage: 'https://packagist.org/', description: 'PHP package registry' },
  { slug: 'rust', displayName: 'crates.io', canonical: 'rust', category: 'package-manager',
    homepage: 'https://crates.io/', description: 'Rust package registry' },
  { slug: 'hex', displayName: 'Hex', canonical: 'hex', category: 'package-manager',
    homepage: 'https://hex.pm/', description: 'Erlang / Elixir package registry' },
  { slug: 'pub', displayName: 'Pub', canonical: 'pub', category: 'package-manager',
    homepage: 'https://pub.dev/', description: 'Dart / Flutter package registry' },

  // ── OS distros (OSV-backed) ────────────────────────────────────────────────
  { slug: 'debian', displayName: 'Debian', canonical: 'Debian', category: 'os-distro',
    homepage: 'https://www.debian.org/security/', description: 'Debian Security Advisories (DSA)' },
  { slug: 'ubuntu', displayName: 'Ubuntu', canonical: 'Ubuntu', category: 'os-distro',
    homepage: 'https://ubuntu.com/security/notices', description: 'Ubuntu Security Notices (USN)' },
  { slug: 'red-hat', displayName: 'Red Hat', canonical: 'Red Hat', category: 'os-distro',
    homepage: 'https://access.redhat.com/security/security-updates/', description: 'Red Hat Enterprise Linux advisories (RHSA)' },
  { slug: 'rocky-linux', displayName: 'Rocky Linux', canonical: 'Rocky Linux', category: 'os-distro',
    homepage: 'https://errata.rockylinux.org/', description: 'Rocky Linux errata (RLSA)' },
  { slug: 'almalinux', displayName: 'AlmaLinux', canonical: 'AlmaLinux', category: 'os-distro',
    homepage: 'https://errata.almalinux.org/', description: 'AlmaLinux errata (ALSA)' },
  { slug: 'suse', displayName: 'SUSE', canonical: 'SUSE', category: 'os-distro',
    homepage: 'https://www.suse.com/support/security/', description: 'SUSE Linux Enterprise advisories (SUSE-SU)' },
  { slug: 'opensuse', displayName: 'openSUSE', canonical: 'openSUSE', category: 'os-distro',
    homepage: 'https://www.suse.com/support/update/', description: 'openSUSE Leap + Tumbleweed advisories' },
  { slug: 'openeuler', displayName: 'openEuler', canonical: 'openEuler', category: 'os-distro',
    homepage: 'https://www.openeuler.org/security/', description: 'openEuler Linux distribution advisories' },
  { slug: 'alpine', displayName: 'Alpine', canonical: 'Alpine', category: 'os-distro',
    homepage: 'https://secdb.alpinelinux.org/', description: 'Alpine Linux security database (secdb)' },
  { slug: 'mageia', displayName: 'Mageia', canonical: 'Mageia', category: 'os-distro',
    homepage: 'https://advisories.mageia.org/', description: 'Mageia Linux advisories (MGASA)' },

  // ── Container distros (OSV-backed, high-volume rebuild advisories) ─────────
  { slug: 'chainguard', displayName: 'Chainguard', canonical: 'Chainguard', category: 'container-distro',
    homepage: 'https://images.chainguard.dev/', description: 'Chainguard zero-CVE container images' },
  { slug: 'wolfi', displayName: 'Wolfi', canonical: 'Wolfi', category: 'container-distro',
    homepage: 'https://wolfi.dev/', description: 'Wolfi Linux distro (Chainguard community distro)' },
  { slug: 'minimos', displayName: 'MinimOS', canonical: 'MinimOS', category: 'container-distro',
    homepage: 'https://minimos.dev/', description: 'Minimal OS for container images' },
  { slug: 'root', displayName: 'Root', canonical: 'Root', category: 'container-distro',
    description: 'Root.io secure container base images' },
  { slug: 'alpaquita', displayName: 'Alpaquita', canonical: 'Alpaquita', category: 'container-distro',
    homepage: 'https://bell-sw.com/alpaquita-linux/', description: 'BellSoft Alpaquita Linux for containers' },
  { slug: 'bellsoft', displayName: 'BellSoft Hardened Containers', canonical: 'BellSoft Hardened Containers', category: 'container-distro',
    homepage: 'https://bell-sw.com/', description: 'BellSoft hardened container image advisories' },
  { slug: 'echo', displayName: 'Echo', canonical: 'Echo', category: 'container-distro',
    description: 'Echo container distribution advisories' },
  { slug: 'cleanstart', displayName: 'CleanStart', canonical: 'CleanStart', category: 'container-distro',
    description: 'CleanStart container base advisories' },

  // ── Kernel & misc (OSV-backed, miscellaneous ecosystems) ───────────────────
  { slug: 'linux', displayName: 'Linux kernel', canonical: 'Linux', category: 'kernel-misc',
    homepage: 'https://www.kernel.org/', description: 'Linux kernel CVEs (kernel.org + linuxkernelcves.com)' },
  { slug: 'android', displayName: 'Android', canonical: 'Android', category: 'kernel-misc',
    homepage: 'https://source.android.com/docs/security/bulletin', description: 'Android Security Bulletins (ASB)' },
  { slug: 'oss-fuzz', displayName: 'OSS-Fuzz', canonical: 'OSS-Fuzz', category: 'kernel-misc',
    homepage: 'https://google.github.io/oss-fuzz/', description: 'Google OSS-Fuzz discovered vulnerabilities' },
  { slug: 'git', displayName: 'GIT (OSV commit tracker)', canonical: 'GIT', category: 'kernel-misc',
    description: 'OSV commit-level tracker for upstream kernel / OSS fixes' },
  { slug: 'gsd', displayName: 'Global Security Database', canonical: 'GSD', category: 'kernel-misc',
    homepage: 'https://gsd.id/', description: 'Cloud Security Alliance Global Security Database' },
  { slug: 'hackage', displayName: 'Hackage', canonical: 'Hackage', category: 'kernel-misc',
    homepage: 'https://hackage.haskell.org/', description: 'Haskell package registry (note: OSV-ingested, not GHSA)' },
  { slug: 'ghc', displayName: 'GHC', canonical: 'GHC', category: 'kernel-misc',
    homepage: 'https://www.haskell.org/ghc/', description: 'Glasgow Haskell Compiler security advisories' },
  { slug: 'cran', displayName: 'CRAN', canonical: 'CRAN', category: 'kernel-misc',
    homepage: 'https://cran.r-project.org/', description: 'Comprehensive R Archive Network' },
  { slug: 'julia', displayName: 'Julia', canonical: 'Julia', category: 'kernel-misc',
    homepage: 'https://julialang.org/', description: 'Julia language package advisories' },
  { slug: 'swifturl', displayName: 'SwiftURL', canonical: 'SwiftURL', category: 'kernel-misc',
    description: 'Swift package advisories (OSV-tracked)' },
  { slug: 'uvi', displayName: 'UVI', canonical: 'UVI', category: 'kernel-misc',
    description: 'Unreviewed Vulnerability Identifier (OSV staging bucket)' },
  { slug: 'bitnami', displayName: 'Bitnami', canonical: 'Bitnami', category: 'kernel-misc',
    homepage: 'https://github.com/bitnami/vulndb', description: 'Bitnami vulnerability database (application images)' },
  { slug: 'vscode', displayName: 'VSCode', canonical: 'VSCode', category: 'kernel-misc',
    homepage: 'https://marketplace.visualstudio.com/', description: 'VSCode extension marketplace advisories' },
];

// ── Validation at module load ────────────────────────────────────────────────
// Fails the build (thrown at import time) on malformed entries. Prevents a
// stored-XSS vector via a `javascript:` homepage URL, slug regex mismatches,
// duplicate slugs, etc.

const ALLOWED_PROTOCOLS = new Set(['https:', 'http:']);
const SLUG_RE = /^[a-z0-9-]{1,64}$/;

function validateMeta(m: EcosystemMeta): void {
  if (!SLUG_RE.test(m.slug)) {
    throw new Error(`[ecosystems.ts] bad slug "${m.slug}" — must match ${SLUG_RE}`);
  }
  if (!m.displayName || m.displayName.length > 80) {
    throw new Error(`[ecosystems.ts] ${m.slug}: displayName empty or > 80 chars`);
  }
  if (!m.canonical) {
    throw new Error(`[ecosystems.ts] ${m.slug}: canonical required`);
  }
  if (!m.description || m.description.length > 300) {
    throw new Error(`[ecosystems.ts] ${m.slug}: description empty or > 300 chars`);
  }
  if (m.homepage) {
    let u: URL;
    try { u = new URL(m.homepage); } catch {
      throw new Error(`[ecosystems.ts] ${m.slug}: homepage malformed URL`);
    }
    if (!ALLOWED_PROTOCOLS.has(u.protocol)) {
      throw new Error(
        `[ecosystems.ts] ${m.slug}: homepage must be http:/https: (got ${u.protocol})`,
      );
    }
  }
}

const seenSlugs = new Set<string>();
const seenCanonical = new Set<string>();
for (const m of REGISTRY) {
  validateMeta(m);
  if (seenSlugs.has(m.slug)) {
    throw new Error(`[ecosystems.ts] duplicate slug: ${m.slug}`);
  }
  if (seenCanonical.has(m.canonical)) {
    throw new Error(`[ecosystems.ts] duplicate canonical: ${m.canonical}`);
  }
  seenSlugs.add(m.slug);
  seenCanonical.add(m.canonical);
}

// ── Exports ──────────────────────────────────────────────────────────────────

export const ECOSYSTEM_REGISTRY: ReadonlyMap<string, EcosystemMeta> = new Map(
  REGISTRY.map((m) => [m.slug, m]),
);

/** Reverse lookup: DB canonical name → metadata. Used when the API receives
 *  a raw ecosystem string (not a slug) and needs to resolve it to a URL. */
export const ECOSYSTEM_BY_CANONICAL: ReadonlyMap<string, EcosystemMeta> = new Map(
  REGISTRY.map((m) => [m.canonical, m]),
);

/** All slugs in display order (for the /ecosystems list page iteration). */
export const ALL_ECOSYSTEM_SLUGS: readonly string[] = REGISTRY.map((m) => m.slug);

/** Slugs grouped by category — drives the 4 collapsible grids on /ecosystems. */
export const ECOSYSTEMS_BY_CATEGORY: Record<EcosystemCategory, readonly string[]> = {
  'package-manager': REGISTRY.filter((m) => m.category === 'package-manager').map((m) => m.slug),
  'os-distro': REGISTRY.filter((m) => m.category === 'os-distro').map((m) => m.slug),
  'container-distro': REGISTRY.filter((m) => m.category === 'container-distro').map((m) => m.slug),
  'kernel-misc': REGISTRY.filter((m) => m.category === 'kernel-misc').map((m) => m.slug),
};

export const CATEGORY_LABELS: Record<EcosystemCategory, string> = {
  'package-manager': 'Package Managers',
  'os-distro': 'OS & Distros',
  'container-distro': 'Container Distros',
  'kernel-misc': 'Kernel & Misc',
};

/**
 * Render-time guard — use for every `<a href={meta.homepage}>`. Returns
 * undefined for anything that isn't HTTP/HTTPS, even if the registry
 * somehow slipped past module-load validation.
 */
export function safeHref(url?: string): string | undefined {
  if (!url) return undefined;
  try {
    return ALLOWED_PROTOCOLS.has(new URL(url).protocol) ? url : undefined;
  } catch {
    return undefined;
  }
}
