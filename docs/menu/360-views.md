# 360 Views

**URL:** `/` (the landing page)
**View:** `src/views/Relationships.tsx`

Single entry point where you pick any entity and see every relationship it has across domains, tabs, frameworks, and graph form.

---

## Problem this solves

Early versions of the tool had per-entity pages (`/techniques/…`, `/groups/…`, etc.) but users kept asking "**what if I don't remember which one I need?**" or "**I want to see all relationships regardless of the entity type**". A CVE analyst and a SOC analyst and an auditor all enter the tool thinking about different primary entities — technique, threat actor, OWASP category, application, sector — but want the same shape of answer: _what touches this?_

360 Views is the polyglot landing page that normalises that intent.

---

## Audience

| Persona | What they typically type | What they want |
|---|---|---|
| SOC analyst | `T1059`, `PowerShell`, `phishing` | Groups, detections, mitigations for this technique |
| Threat-intel analyst | `APT29`, `Lazarus`, `Cobalt Strike` | Actor profile — sectors, software, campaigns, techniques |
| CISO / exec | `financial sector`, `healthcare` | Sector-level threat landscape |
| App-sec engineer | `litellm`, `apache/tomcat`, `npm/react` | App vulnerability posture + reachable techniques |
| Compliance auditor | `A01`, `LLM01` | OWASP category → technique → control mapping |
| AI agent | same, via A2A tools | Same data, machine-readable |

---

## Design decisions

### 1. One URL, many views — not one URL per entity type

**Chose:** `/?entity=<id>&tab=<map>` — a single route that infers entity type and swaps the view.
**Alternative considered:** routes-per-type like `/relationships/technique/T1059`, `/relationships/group/G0016`.
**Why we picked the unified URL:** entity type detection (from search suggestions, graph center node, or ID regex) is already cheap; separate routes would force users to know the type before they type. The unified search bar serves the "I don't know, just show me what's here" use case.

### 2. Tab set per entity type

**Chose:** tabs are `forTypes`-gated. A technique shows `Technique Map` + `Graph`, a group shows `Threat Actor Profile` + `Graph`, a sector shows `Sector Map` + `Graph`, and so on.
**Alternative considered:** a universal tab layout with empty states for irrelevant tabs.
**Why we picked gated tabs:** fewer dead ends, cleaner URL bookmarking, the default-tab-on-type is more useful than a consistent-but-empty tab.

### 3. "Diamond Entities" branding

The title and iconography nod to the Diamond Model of Intrusion Analysis (Actor/Adversary · Capability/Technique · Infrastructure/Application · Victim/Sector). The 4 corner labels on the landing diamond match those 4 vertices and colour-code consistently across the rest of the UI.

### 4. Start-here hint on an empty state

The search bar on the empty landing state shows an animated `← Start here` hint on desktop (hidden on touch), slightly enlarged input, and a subtle teal glow — because new users were bouncing off the blank-looking page. This was an explicit UX fix after the first user-testing round.

---

## Filter decisions

The 360 Views page itself has only one global filter: **Domain** (from the sidebar).

| Filter | Default | Options | Why |
|---|---|---|---|
| **Domain** | `all` | `all`, `enterprise-attack`, `mobile-attack`, `ics-attack`, `atlas-attack` | Users working in ICS don't want enterprise noise; AI-security researchers want ATLAS only. Applied via `DomainContext` and persisted in `sessionStorage`. |
| **Sector** (sidebar) | none | Any sector slug (12 built-in) | Scopes group/software/campaign fan-out on technique maps — "show me only financial-sector groups" |

Per-tab filters live in each map view (e.g. Technique Map has a sector toggle on groups/software, sub-technique expand). See the component files (`TechniqueMapView.tsx`, `SectorMapView.tsx`, etc.) for tab-local filter contracts.

### Why no severity / date filter at the top level

Tried: a global `?severity` query param that filters CVEs shown under applications and techniques.
Dropped: the entity-first mental model (my technique → my CVEs) is different from the severity-first one (critical CVEs → affected techniques). Severity belongs on `/cti/cves` and `/cti/advisories`, not the 360-map surface.

---

## Data flow

```
user types "APT29"
     ↓
useFuse (pre-loaded /entities cross-domain list, 1h cache)
     ↓
suggestion: { attackId: 'G0016', type: 'group', name: 'APT29' }
     ↓
URL → /?entity=G0016&tab=actor
     ↓
activeTab=actor renders <ActorProfileView attackId='G0016'/>
     ↓
ActorProfileView internally fires /api/v1/groups/G0016 (TanStack Query)
     ↓
Actor profile renders: techniques, software, campaigns, sectors, apps, reports
```

Entity-type detection order (from `inferEntityType`):
1. Graph center node's `type` (if graph loaded)
2. OWASP ID regex (`A01`, `ML01`, `LLM01`)
3. Application slug regex (`vendor/product`)
4. Search suggestion match
5. null → user sees a "still loading" state until one of the above resolves

---

## Data sources

- **MITRE ATT&CK STIX** (v18.1 — Enterprise, ICS, Mobile)
- **MITRE ATLAS** (v1.0 — AI/ML)
- Materialized view `app_technique_groups` (189 MB, refreshed every 8h via `/api/cron/refresh-matviews`) for application-side fan-out
- Live queries against `techniques`, `groups`, `campaigns`, `software`, `mitigations`, `data_sources`, `tactics`, `sectors`, `applications`, `affected_products`, `capec_mappings`

---

## Tradeoffs

| What we don't do | Why |
|---|---|
| Return server-rendered HTML for each map | Client-side React + TanStack Query gives us instant re-navigation when users pivot via graph node click. Server-render would double the TTFB on each pivot. |
| Allow cross-domain graph (e.g. enterprise T1059 + ATLAS node in same view) | Would require unifying the force-graph key space and is marginal value for the audience. |
| Memoize the Fuse.js index longer than 1h | Entities rarely change but the ingest crons do add new apps/techniques weekly; 1h keeps us fresh without hammering the API. |

---

## History

- Originally called "Relationships Map" in the sidebar; renamed to "360 Views" after user confusion about what "Relationships Map" meant.
- The page title "Diamond Entities" was also renamed from "Entity Relationships" to lean into the Diamond Model analogy.
- Added `ForceGraph` dynamic import mid-2026 to avoid shipping the graph lib on pages that don't need it.
- Added the `OWASP Map` tab after OWASP Top 10 integration; added `Application Map` tab after the applications pivot launched.
- Recent (2026-04): removed "Data Source" from the landing search/legend per user preference — data-source browsing still works via direct URL or sidebar Defensive section, just isn't advertised on the empty-state page.

---

## Cross-refs

- Full API surface behind map tabs: [`docs/feeds_setup.md`](../feeds_setup.md)
- Technique map card composition: [`src/components/relationships/TechniqueMapView.tsx`](../../src/components/relationships/TechniqueMapView.tsx)
- Actor profile composition: [`src/components/relationships/ActorProfileView.tsx`](../../src/components/relationships/ActorProfileView.tsx)
- A2A equivalent for agents: `get_technique_intelligence`, `get_group_profile`, `get_sector_threats`, `get_application_security` (see [agent-card.json](../../public/.well-known/agent-card.json))
