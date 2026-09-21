/**
 * On-demand usage guide for the agent tool catalogue.
 *
 * Deliberately NOT in any tool description: this is the detail a model needs
 * AFTER it has chosen a tool, and tool descriptions are loaded into every
 * client context on every conversation. It is served two ways -- as an MCP
 * resource (mitre://guide) and by the get_usage_guide tool -- because some
 * clients surface resources only on explicit user action, whereas a tool is
 * reliably reachable by the model itself.
 *
 * What must NOT move in here: anything whose absence would let a model state
 * something false (the version-is-not-a-verdict caveat, curated-vs-published
 * provenance, empty-means-authoritative). Those stay in the descriptions,
 * because a client may never load this.
 *
 * Vocabularies below are verified against production, not transcribed.
 */
export const USAGE_GUIDE = `# MITRE Explorer — agent usage guide

## The one rule
Always call a tool before answering. This data changes continuously (CVEs, advisories, KEV) and model training data is stale. Never answer a factual question about a technique, CVE, group or advisory from memory.

## search_ vs get_
- **search_*** returns summaries for discovery. **get_*** returns the full record for one entity.
- Standard two-step: if you have a name but not an ID, call the search_ tool to resolve the ID, then the get_ tool for detail.
- A search_ result is not a complete profile. Do not answer "which techniques does APT29 use" from search_groups.

## Choosing between similar tools
**Techniques (three tools, none a superset):**
- get_technique_detail -- description, tactics, platforms, sub-techniques, mitigations, data sources, CAPEC, and the threat groups, malware and campaigns that use it.
- get_technique_intelligence -- Sigma rules, Atomic tests, D3FEND defensive mappings, detection strategies, threat reports, linked CVEs, IOCs and affected applications. It returns NO threat groups; those come from get_technique_detail.
- get_technique_compliance -- regulatory frameworks referencing it.
For "tell me about T1059", call the first two. They do not overlap.

**Vulnerabilities:**
- search_cves / get_cve_detail -- CVEs, EPSS, KEV, CAPEC, affected applications.
- search_advisories -- unified GHSA + OSV view. Prefer it for "recent advisories".
- get_ghsa_detail / get_osv_detail -- one advisory by ID.
- get_package_vulnerabilities -- advisories for one ecosystem+package.
- get_cve_packages -- packages affected by one CVE.

**Actors:** get_group_profile (ATT&CK ID) is the TTP source. get_external_actor is ETDA/ThaiCERT reference metadata only, matched on exact name -- a miss there never means the actor is absent; try search_groups.

**Frameworks:** get_framework_mappings for direct ATT&CK mappings (800-53, Engage, VERIS, cloud controls). get_technique_compliance for regulatory frameworks via the SCF crosswalk.

## Provenance -- report it honestly
- **MITRE-published:** techniques, tactics, groups, software, campaigns, mitigations, data sources, ICS assets.
- **Curated by this project:** Purdue level placement for ICS assets (primaryLevel, zone, spansLevels, isBoundary, rationale), derived from NIST SP 800-82r3 and ISA-95. Never attribute it to MITRE.
- **Inferred, lower confidence:** CVE-to-technique links via the CWE -> CAPEC -> ATT&CK bridge. Curated CTID/CISA links are high confidence. Do not present inferred links as confirmed attribution.
- **Version filters** surface advisories whose affected range MENTIONS a version string. That is not a verdict that the version is vulnerable. Say so every time.
- **Empty results** are authoritative where a tool says so (get_technique_compliance, search_assets for a non-ICS question). Elsewhere an empty result means no match on those filters, not that nothing exists. get_cve_packages is NOT authoritative: an empty list means the CVE has no GHSA alias or the lookup failed, never that no package is affected -- check osvAdvisories in get_cve_detail.
- **Heat and coverage** metrics reflect detection relevance, not verified mitigation or compliance.

## Pagination
List tools accept page (default 1) and return pagination with page, limit, total and totalPages. If total exceeds the rows you received, either fetch further pages or state explicitly how many of the total you are showing ("showing 10 of 47"). Never present one page as the complete set.

## Filters fail loudly
An unusable filter value returns an error rather than being dropped, so a result set always reflects every filter you passed. If you get "Invalid sector" or "Invalid since", fix the value and retry -- do not assume the unfiltered answer is close enough.

## ICS and the Purdue model
Seven levels: l0 physical process, l1 basic control, l2 supervisory, l3 site operations, l3_5 industrial DMZ, l4 business logistics, l5 enterprise. Zones: ot (l0-l3), dmz (l3_5), it (l4-l5).
Assets are placed by the levels they SPAN, not only their primary level -- a historian at l3 replicated into the DMZ matches both.
In the flow matrix, **directAllowed means topological adjacency, not permission to initiate**. Always read the note field: l3_5 to l3 is directAllowed, yet the note records that the OT side initiates and a DMZ host must not open sessions inward. A pair with brokerLevel is reachable only by terminating a session at that level first; never read it as adjacency.
MITRE publishes assets for the ICS domain only, so an empty asset result for a non-ICS question is expected rather than missing data.

## Picking the right tool when several look similar
| You want | Call |
| --- | --- |
| Everything about one technique | get_technique_detail AND get_technique_intelligence (neither is a superset) |
| Who uses a technique | get_technique_detail (returns groups) |
| Detection content for a technique | get_technique_intelligence (Sigma, Atomic, D3FEND) |
| Regulations citing a technique | get_technique_compliance |
| A group and its TTPs | search_groups to resolve the ID, then get_group_profile |
| Country, motivation, state sponsor | get_external_actor (metadata only, exact name match) |
| Recent advisories, any ecosystem | search_advisories |
| GitHub advisories with ATT&CK linkage | search_ghsa (returns techniqueCount and withdrawnAt, which search_advisories does not) |
| Advisories for one package | get_package_vulnerabilities |
| Which packages one CVE affects | get_cve_packages |
| ICS equipment and where it sits | search_assets, then get_asset_detail |
| Which plant levels may talk | get_purdue_model |

search_ghsa and search_advisories are NOT interchangeable. search_advisories is the unified GHSA+OSV view; search_ghsa queries the GHSA corpus directly, returns more rows for the same query, and carries techniqueCount and withdrawnAt. Use search_advisories for breadth, search_ghsa when ATT&CK linkage or withdrawal status matters.

## What list rows actually contain
Verified against the live API -- do not assume a field exists because it would be useful:
- Counts are returned ONLY by: search_cves and search_assets (techniqueCount); search_capec (techniqueCount, mitigationCount); search_applications (cveCount, techniqueCount, groupCount); search_iocs (technique_count); search_ghsa (packageCount, techniqueCount); get_threat_reports (technique_count).
- search_groups, search_software, search_campaigns, search_mitigations, search_sigma_rules and search_atomic_tests return NO counts. If you need "how many techniques does this group use", call get_group_profile and count the array; do not report a number the list row never gave you.
- Field naming is camelCase everywhere EXCEPT search_iocs, which returns technique_count in snake_case.
- search_iocs returns a technique COUNT but not the technique IDs, and excludes CVE rows unless type is cve or source is cisa_kev.
- Text search on the ATT&CK entity lists (groups, software, campaigns, mitigations) is Postgres full-text over name and description with a 3-character minimum -- it is not a substring match, so a partial word may not match. Revoked and deprecated entries are excluded by default.

## Vocabularies
**Sectors** (search_groups, search_software, search_campaigns, get_sector_threats, get_dashboard_stats): defense, education, energy, financial, government, healthcare, manufacturing, media, retail, technology, telecommunications, transportation.

**OWASP frameworks** (get_owasp_top10): web-2021, ml-2023, llm-2025.

**Compliance framework keys** (get_compliance_framework) -- Tier 1: eu-nis2, eu-ai-act, gdpr, eu-cra, pci-dss-4, iso-27002-2022, nist-csf-v2, owasp-top10-2025, nist-800-53-r5, soc-2-tsc, cmmc-2, hipaa-security-rule. Tier 2: au-essential-8, eu-dora, iec-62443, cis-controls-8-1, nist-ai-rmf, uk-cyber-essentials, fedramp-r5, nist-800-171-r3, nerc-cip-2024. An unknown key returns 404 -- never invent one; call list_compliance_frameworks if unsure.

**ATT&CK domains:** enterprise-attack, ics-attack, mobile-attack, atlas-attack.
`;
