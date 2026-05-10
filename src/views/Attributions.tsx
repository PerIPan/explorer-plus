import { PageHeader } from '../components/layout/PageHeader';
import { Badge } from '../components/shared/Badge';

interface Source {
  name: string;
  url: string;
  license: string;
  licenseUrl?: string;
  blurb: string;
}

// Grouped per license class so users can see at a glance what's permissive vs
// share-alike. URLs point to the authoritative upstream, never to our copy.

const PUBLIC_DOMAIN: Source[] = [
  { name: 'NIST 800-53 Rev. 5', url: 'https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final', license: 'Public domain (17 USC §105)', blurb: 'Security and privacy controls for federal information systems.' },
  { name: 'NIST CSF v2', url: 'https://www.nist.gov/cyberframework', license: 'Public domain (17 USC §105)', blurb: 'Cybersecurity Framework v2 subcategories + CRI Profile crosswalk.' },
  { name: 'NIST 800-66 r2', url: 'https://csrc.nist.gov/publications/detail/sp/800-66/rev-2/final', license: 'Public domain', blurb: 'HIPAA Security Rule implementation guidance.' },
  { name: 'CISA Known Exploited Vulnerabilities', url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog', license: 'Public domain', blurb: 'Vulnerabilities known to be actively exploited in the wild.' },
  { name: 'NVD (NIST National Vulnerability Database)', url: 'https://nvd.nist.gov/', license: 'Public domain', blurb: 'CVE metadata, CVSS scores, CPE enrichment.' },
  { name: 'MITRE CWE', url: 'https://cwe.mitre.org/', license: 'Public domain (DHS-funded)', blurb: 'Common Weakness Enumeration taxonomy.' },
];

const PERMISSIVE: Source[] = [
  { name: 'MITRE ATT&CK', url: 'https://attack.mitre.org/', license: 'Apache 2.0', licenseUrl: 'https://github.com/mitre-attack/attack-stix-data/blob/master/LICENSE.txt', blurb: 'Adversary tactics, techniques, sub-techniques, groups, software, campaigns, mitigations, data sources/components.' },
  { name: 'MITRE CAPEC', url: 'https://capec.mitre.org/', license: 'Public domain (DHS-funded)', blurb: 'Common Attack Pattern Enumeration and Classification — full taxonomy + CWE→ATT&CK bridge.' },
  { name: 'MITRE D3FEND', url: 'https://d3fend.mitre.org/', license: 'MIT', licenseUrl: 'https://github.com/d3fend/d3fend-ontology/blob/main/LICENSE', blurb: 'Defensive countermeasure knowledge graph mapped to ATT&CK.' },
  { name: 'MITRE Engage', url: 'https://engage.mitre.org/', license: 'Apache 2.0', blurb: 'Adversary engagement / deception activity mappings.' },
  { name: 'CTID (Center for Threat-Informed Defense)', url: 'https://github.com/center-for-threat-informed-defense', license: 'Apache 2.0', licenseUrl: 'https://github.com/center-for-threat-informed-defense/attack_to_cve/blob/main/LICENSE', blurb: 'Hand-curated CVE → ATT&CK technique mappings.' },
  { name: 'VERIS', url: 'https://verisframework.org/', license: 'Apache 2.0', licenseUrl: 'https://github.com/vz-risk/veris/blob/master/LICENSE', blurb: 'Verizon DBIR Vocabulary for Event Recording and Incident Sharing.' },
  { name: 'RE&CT', url: 'https://atc-project.github.io/atc-react/', license: 'MIT', licenseUrl: 'https://github.com/atc-project/atc-react/blob/master/LICENSE', blurb: 'ATC incident response playbook actions.' },
  { name: 'SigmaHQ', url: 'https://github.com/SigmaHQ/sigma', license: 'Detection Rule License (permissive)', licenseUrl: 'https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md', blurb: '3,000+ detection rules mapped to ATT&CK techniques.' },
  { name: 'Atomic Red Team', url: 'https://github.com/redcanaryco/atomic-red-team', license: 'MIT', licenseUrl: 'https://github.com/redcanaryco/atomic-red-team/blob/master/LICENSE.txt', blurb: '1,700+ adversary-emulation tests.' },
  { name: 'abuse.ch (ThreatFox + MalwareBazaar)', url: 'https://abuse.ch/', license: 'CC0', blurb: 'Public-domain malware-family + IOC feeds (IPs, domains, URLs, hashes).' },
  { name: 'CVElistV5', url: 'https://github.com/CVEProject/cvelistV5', license: 'CC0 (CVE Program)', blurb: 'Authoritative CVE Program JSON feed — what NIST NVD consumes.' },
];

const ATTRIBUTION_REQUIRED: Source[] = [
  { name: 'MITRE ATLAS', url: 'https://atlas.mitre.org/', license: 'CC BY 4.0', licenseUrl: 'https://creativecommons.org/licenses/by/4.0/', blurb: 'AI/ML adversarial threat techniques + mitigations.' },
  { name: 'OWASP Top 10 (Web 2021, ML 2023, LLM 2025)', url: 'https://owasp.org/Top10/', license: 'CC BY-SA 4.0', licenseUrl: 'https://creativecommons.org/licenses/by-sa/4.0/', blurb: 'Web, ML, and LLM security-risk categories — used with attribution to OWASP.' },
  { name: 'OSV.dev', url: 'https://osv.dev/', license: 'CC BY 4.0', licenseUrl: 'https://google.github.io/osv.dev/faq/', blurb: 'Distributed vulnerability database for open-source projects (Google).' },
  { name: 'GHSA (GitHub Security Advisories)', url: 'https://github.com/advisories', license: 'CC BY 4.0', licenseUrl: 'https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features#advisory-database', blurb: 'OSS package advisories — npm, PyPI, Maven, Go, RubyGems, Composer, Rust, etc.' },
  { name: 'EPSS (FIRST.org)', url: 'https://www.first.org/epss/', license: 'CC BY 4.0', licenseUrl: 'https://www.first.org/epss/data_access', blurb: 'Exploit Prediction Scoring System — daily probability scores per CVE.' },
  { name: 'ThaiCERT / ETDA Actor Encyclopedia', url: 'https://apt.etda.or.th/', license: 'CC BY 4.0', blurb: '500+ external threat-actor profiles.' },
];

const ENRICHMENT_API: Source[] = [
  { name: 'AlienVault OTX', url: 'https://otx.alienvault.com/', license: 'OTX community contribution terms', blurb: 'Threat-report pulses + IOC indicators consumed via API.' },
  { name: 'VirusTotal', url: 'https://www.virustotal.com/', license: 'VirusTotal Terms of Service', blurb: 'Domain and file-hash verdict counts (malicious/suspicious/harmless) — only aggregate verdicts stored, no full report content redistributed.' },
];

const RSS_FEEDS: Source[] = [
  { name: 'The DFIR Report', url: 'https://thedfirreport.com/', license: 'Article copyright respective authors; we store title + URL + summary for indexing.', blurb: 'Incident-response intrusion writeups.' },
  { name: 'Unit 42 (Palo Alto Networks)', url: 'https://unit42.paloaltonetworks.com/', license: 'Article copyright PANW; indexed.', blurb: 'Threat-intel research blog.' },
  { name: 'Microsoft Security Blog', url: 'https://www.microsoft.com/security/blog/', license: 'Article copyright Microsoft; indexed.', blurb: 'Microsoft threat research.' },
  { name: 'Cisco Talos', url: 'https://blog.talosintelligence.com/', license: 'Article copyright Cisco Talos; indexed.', blurb: 'Talos threat-intel research.' },
];

function SourceTable({ rows }: { rows: Source[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-[var(--border-color)]">
      <table className="w-full text-sm">
        <thead className="bg-[var(--surface-deep)] text-left text-xs uppercase tracking-wider text-[var(--text-secondary)]">
          <tr>
            <th className="px-3 py-2 font-semibold">Source</th>
            <th className="px-3 py-2 font-semibold">License</th>
            <th className="px-3 py-2 font-semibold">What we use</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border-color)]">
          {rows.map((r) => (
            <tr key={r.name} className="bg-[var(--surface-card)]">
              <td className="px-3 py-2">
                <a href={r.url} target="_blank" rel="noopener noreferrer" className="text-[var(--accent-teal)] hover:underline font-medium">{r.name}</a>
              </td>
              <td className="px-3 py-2 text-xs">
                {r.licenseUrl
                  ? <a href={r.licenseUrl} target="_blank" rel="noopener noreferrer" className="text-[var(--text-secondary)] hover:text-[var(--accent-teal)] hover:underline">{r.license}</a>
                  : <span className="text-[var(--text-secondary)]">{r.license}</span>}
              </td>
              <td className="px-3 py-2 text-xs text-[var(--text-secondary)] leading-relaxed">{r.blurb}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Attributions() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="Data attributions"
        subtitle="Every external data source ingested into MITRE Explorer Plus, grouped by license class"
      />

      <div className="rounded-lg border border-[var(--blue-dim)] bg-[var(--blue-faint)] px-4 py-3 text-sm">
        <p className="text-[var(--text-primary)]">
          MITRE Explorer Plus aggregates ~30 authoritative threat-intelligence, vulnerability, and compliance feeds.
          The application code is ISC-licensed; the underlying data inherits each source&rsquo;s upstream license.
          Below is the full inventory + the upstream URLs you should cite if you derive further work from anything you see here.
        </p>
      </div>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3 flex items-center gap-2">
          Public domain
          <Badge label="no attribution required" variant="green" />
        </h2>
        <p className="text-xs text-[var(--text-secondary)] mb-2">
          Works of the United States government (17 USC §105) — free to use, modify, and redistribute without restriction or attribution. Attribution still appreciated.
        </p>
        <SourceTable rows={PUBLIC_DOMAIN} />
      </section>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3 flex items-center gap-2">
          Permissive open-source
          <Badge label="attribution appreciated" variant="teal" />
        </h2>
        <p className="text-xs text-[var(--text-secondary)] mb-2">
          MIT / Apache 2.0 / CC0 / Detection Rule License — free for any use, commercial or otherwise. Attribution is appreciated by the upstream maintainers.
        </p>
        <SourceTable rows={PERMISSIVE} />
      </section>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3 flex items-center gap-2">
          Creative Commons (attribution required)
          <Badge label="must credit" variant="yellow" />
        </h2>
        <p className="text-xs text-[var(--text-secondary)] mb-2">
          CC BY 4.0 and CC BY-SA 4.0 — free to use and redistribute provided attribution is given. Share-alike (BY-SA) additionally requires derivative works to carry the same license. This page is part of that attribution.
        </p>
        <SourceTable rows={ATTRIBUTION_REQUIRED} />
      </section>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3 flex items-center gap-2">
          Enrichment APIs
          <Badge label="see ToS" variant="orange" />
        </h2>
        <p className="text-xs text-[var(--text-secondary)] mb-2">
          API-fetched data subject to the provider&rsquo;s terms of service. We store only minimal derived records (aggregate verdicts, summary metadata) and never redistribute full responses.
        </p>
        <SourceTable rows={ENRICHMENT_API} />
      </section>

      <section>
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3 flex items-center gap-2">
          RSS / blog indexing
          <Badge label="fair use" variant="neutral" />
        </h2>
        <p className="text-xs text-[var(--text-secondary)] mb-2">
          Public RSS feeds — we index titles, URLs, and short summaries (typical for an aggregator). Articles remain the copyright of their original publishers.
        </p>
        <SourceTable rows={RSS_FEEDS} />
      </section>

      <section className="pt-4 border-t border-[var(--border-color)]">
        <h2 className="text-sm font-bold uppercase tracking-wider text-[var(--accent-teal)] mb-3">Disclaimers</h2>
        <ul className="space-y-1.5 text-xs text-[var(--text-secondary)] leading-relaxed">
          <li>This site is <strong>not affiliated with, sponsored by, or endorsed by MITRE Corporation</strong>. &ldquo;ATT&amp;CK&rdquo; and &ldquo;ATLAS&rdquo; are registered trademarks of MITRE Corporation.</li>
          <li>OWASP&reg; and the OWASP logo are trademarks of the OWASP Foundation.</li>
          <li>NIST does not endorse this product or service.</li>
          <li>Errors or omissions in attribution? Reach out at <span className="text-[var(--accent-teal)]">contact @ mitre-explorer.org</span>.</li>
        </ul>
      </section>
    </div>
  );
}
