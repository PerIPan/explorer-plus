# OpenCRE Research — Future Integration

**Date:** 2026-04-08
**Status:** Parked — revisit after Next.js migration

## What Is OpenCRE

Universal cross-linking index for security standards (OWASP project). Every standard maps to a shared "CRE" anchor node (star topology) — adding one standard automatically connects it to everything else via transitivity.

**Repo:** https://github.com/OWASP/OpenCRE
**Public API:** https://opencre.org/rest/v1/

## Overlap With MITRE Explorer

Already in both: OWASP Top 10 (web), CWE, CAPEC, NIST 800-53, cloud controls (CCM v4 vs our Azure/GCP).

**Not in OpenCRE:** ATT&CK, CVE, Sigma, Engage, RE&CT, VERIS, ATLAS — our threat intel side is unique.

## High-Value Additions

| Dataset | What | Value |
|---------|------|-------|
| **OWASP ASVS** | 400+ developer security requirements, 3 assurance levels | "How to fix it" counterpart to ATT&CK |
| **OWASP WSTG** | ~90 web security test cases (WSTG-ATHN-01, etc.) | "How to test for it" |
| **PCI DSS v4** | Payment card compliance controls | Essential for fintech users |
| **ISO 27001** | International ISMS standard | Essential for enterprise/EU users |

## Medium-Value Additions

| Dataset | What | Value |
|---------|------|-------|
| **OWASP Cheat Sheets** | ~90 implementation guides | Practical remediation guidance |
| **NIST 800-63** | Digital identity & auth guidelines | Distinct from 800-53 |
| **CNCF Cloud Native Controls** | 345 K8s/container security controls | Cloud-agnostic, complements Azure/GCP |

## Lower-Value (Process/Governance)

OWASP Proactive Controls, OWASP SAMM v2, NIST SSDF, DSOMM — process-focused, less linkable to techniques.

## Diamond Model Integration

The bridge is CWE (already in our system):

```
ATT&CK Technique <-- CAPEC <-- CWE --> CRE --> ASVS requirement
                                            --> WSTG test case
                                            --> Cheat Sheet
                                            --> PCI DSS control
                                            --> ISO 27001 control
```

CRE could become a new entity type — the pivot connecting attack-side (ATT&CK) to defense-side (ASVS, WSTG, PCI).

## Data Access

- No public bulk export — must paginate REST API or run local Docker instance
- `GET /rest/v1/cre?name=<name>&page=N` — search CREs
- `GET /rest/v1/standards` — list all standard names
- `GET /rest/v1/cre_csv` — bulk CSV (local instance only)
- OSCAL 1.0.0 JSON export available per CRE/standard

## CRE Data Structure

```
CRE { id: "NNN-NNN", name, description, tags[], links[] }
Standard { name, section, sectionID, hyperlink, version, links[] }
Link { document, ltype: LinkedTo|Contains|PartOf|Related|AutomaticallyLinkedTo }
```

## Open Questions for Revisit

1. Ingest via API pagination or local Docker bulk export?
2. CRE as entity type or transparent bridge (hidden from UI)?
3. Which frameworks first — ASVS + WSTG (developer audience) or PCI + ISO (compliance audience)?
4. How to handle AI-auto-linked mappings (lower confidence than editorial)?
5. Scope: all ~600 CREs or only those reachable from our existing CWE set?
