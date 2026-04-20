/**
 * Ecosystem categorisation for the unified Advisories list.
 *
 * The raw ecosystem list on osv-vulnerabilities is a flat 30+ names. For the
 * list UI a flat dropdown is unscannable, so we group them into four coarse
 * categories that match the audiences we care about:
 *
 *   - oss-packages: GHSA-covered OSS language packages (our GHSA ingest).
 *     Audience: dev, SBOM/SCA workflows.
 *   - real-distro:  Ubuntu / Debian / RHEL / SUSE / openSUSE / AlmaLinux /
 *     Rocky / Alpine / Mageia / Red Hat / openEuler. Audience: sysadmin / SRE.
 *   - container-distro: Chainguard / Wolfi / MinimOS / Root / Alpaquita /
 *     BellSoft Hardened Containers / Echo / CleanStart. These distros rebuild
 *     upstream CVEs into per-image advisories at very high volume. Audience:
 *     container SRE / supply chain.
 *   - kernel-misc: Linux kernel, Android, OSS-Fuzz, GIT, GSD, Hackage, CRAN,
 *     Julia, GHC, SwiftURL, UVI, Bitnami, VSCode. Audience: everything that
 *     doesn't fit the above buckets.
 *
 * This categorisation is editorial. Keep it up to date as OSV adds new
 * ecosystems — run `SELECT DISTINCT ecosystem FROM osv_advisories` after
 * each monthly full reconcile to spot newcomers.
 */

export type AdvisoryEcosystemCategory =
  | 'oss-packages'
  | 'real-distro'
  | 'container-distro'
  | 'kernel-misc';

export const ADVISORY_ECOSYSTEM_CATEGORIES: Record<
  AdvisoryEcosystemCategory,
  { label: string; ecosystems: string[] }
> = {
  'oss-packages': {
    label: 'OSS package advisories (GHSA)',
    // GHSA ecosystems use lowercase names internally (see /api/v1/advisories
    // route — GHSA branch lowercases ecosystem filter). API accepts these.
    ecosystems: ['npm', 'pypi', 'go', 'maven', 'rubygems', 'nuget', 'composer', 'rust', 'hex', 'pub'],
  },
  'real-distro': {
    label: 'OS & distros (Debian, Ubuntu, RHEL, SUSE, Alpine, …)',
    ecosystems: [
      'Ubuntu', 'Debian', 'Red Hat', 'Rocky Linux', 'AlmaLinux',
      'SUSE', 'openSUSE', 'openEuler', 'Alpine', 'Mageia',
    ],
  },
  'container-distro': {
    label: 'Container-image distros (Chainguard, Wolfi, MinimOS, …)',
    ecosystems: [
      'Chainguard', 'Wolfi', 'MinimOS', 'Root', 'Alpaquita',
      'BellSoft Hardened Containers', 'Echo', 'CleanStart',
    ],
  },
  'kernel-misc': {
    label: 'Kernel, Android, fuzzing & misc (Linux, Android, OSS-Fuzz, …)',
    ecosystems: [
      'Linux', 'Android', 'OSS-Fuzz', 'GIT', 'GSD',
      'Hackage', 'CRAN', 'Julia', 'GHC', 'SwiftURL', 'UVI', 'Bitnami', 'VSCode',
    ],
  },
};

export const ADVISORY_CATEGORY_KEYS: AdvisoryEcosystemCategory[] = [
  'oss-packages',
  'real-distro',
  'container-distro',
  'kernel-misc',
];
