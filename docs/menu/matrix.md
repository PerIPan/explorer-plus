# Matrix

**URL:** `/matrix` (optional `?domain=<domain>&actor=<groupId>&entity=<id>&type=<type>&label=<label>`)
**View:** `src/views/Matrix.tsx`

Classic ATT&CK-style tactic × technique heatmap, filterable by actor or entity.

---

## Problem this solves

ATT&CK is usually experienced as a giant grid — rows are tactics (Initial Access → Impact), columns group techniques under each. For our users two specific questions pulled us to build our own version rather than link to attack.mitre.org:

1. "Which techniques does **this specific threat group** use?" → overlay group usage on the matrix
2. "How does the matrix look when filtered by **the specific entity I'm working with** (a CVE, a Sigma rule, a mitigation)?" → cross-entity matrix filter

The vanilla ATT&CK matrix doesn't overlay group/entity context; we needed that overlay.

---

## Audience

| Persona | Usage pattern |
|---|---|
| Red team | "Show me APT29's full technique spread" — visual gap analysis before an engagement |
| Purple team | "Which tactics do we have detection for?" — heatmap-style coverage review |
| Threat analyst | "This mitigation protects against which techniques?" — audit a control's coverage |
| CISO presentation | Matrix with an actor filter = one-pager threat briefing |

---

## Design decisions

### 1. Heatmap cells, not just text

**Chose:** each cell is colour-weighted by "how used" the technique is within the current filter. Darker = more groups/campaigns reference it.
**Alternative considered:** flat grid with ticks.
**Why:** flat grid hides the signal. Heat lets the eye jump to heavily-used techniques.

### 2. Sub-technique collapse

Default view shows parent techniques only; sub-techniques expand on click. Otherwise the grid becomes 5–7 rows tall per tactic and unreadable.

### 3. "Actor overlay" is a query param, not a separate page

`?actor=G0016` overlays APT29 usage as a second colour channel on top of the standard heat. Deep-linkable, easily shared.

### 4. Bidirectional entity filter

Any entity 360 page has a "Matrix ↗" button that deep-links to `/matrix?type=<entityType>&entity=<id>&label=<name>`. The matrix then filters to techniques reachable from that entity. Closes the loop: technique → groups → campaigns → matrix → back to a specific technique's 360.

### 5. No click-through from a matrix cell by default

Cells do NOT link to `/techniques/<id>` on click; they expand a popover with summary + link. Click-through-on-cell was tested and rejected because a single misclick would take a reviewing analyst out of their gap-analysis flow.

---

## Filter decisions

| Filter | Default | Options | Why |
|---|---|---|---|
| **Domain** | `enterprise-attack` (or sidebar override) | `enterprise`, `mobile`, `ics`, `atlas` | The matrix shape differs per domain; mixing them would break tactic columns |
| **Actor** | none | Any group ATT&CK ID (e.g. `G0016`) | Overlay usage per-group. Supports comma-separated list for side-by-side comparison (_"APT28 vs APT29"_) |
| **Entity filter** | none | Any ATT&CK ID / IOC / Sigma rule / Atomic test ID | Filters the matrix down to techniques reachable from the entity |
| **Label** (read-only display) | derived from entity | — | Shown in the header so users remember what they filtered by |
| **Sector** (sidebar) | none | Sector slug | Further narrows actor overlay to groups targeting that sector |

### Why no "severity" or "date" filter on matrix

The matrix is structural, not temporal. A technique exists or doesn't; it doesn't have severity. Date-filtering techniques doesn't make sense at this scope.

### Why no "platform" filter

ATT&CK's own matrix has platform sub-filters (Windows/Linux/macOS). We removed this initially because domain filter (enterprise/mobile/ics/atlas) serves the same purpose for our audience. It could be added back if users ask.

---

## Data flow

```
user hits /matrix?domain=enterprise-attack&actor=G0016
        ↓
useMatrixData(domain, actor)
        ↓
/api/v1/matrix?domain=…&actor=…
        ↓
SQL: tactics × techniques LEFT JOIN group_techniques WHERE group_id = $actor
        ↓
Matrix grid renders with heat cells + popovers
```

---

## Data sources

- `tactics` + `techniques` + `technique_tactics` (raw ATT&CK STIX)
- `group_techniques`, `campaign_techniques`, `software_techniques` — for usage counts
- Optional filter joins into `sigma_rules`, `technique_iocs`, `atomic_tests`, `mitigation_techniques`

---

## Tradeoffs

| What we don't do | Why |
|---|---|
| Server-render the grid | Client-side React makes the actor-overlay change re-render cheap; server would force full reload |
| Persist the user's last-selected filters across sessions | URL params already serialise the state; cookies or localStorage would add stale-state complexity |
| Support the full ATT&CK sub-technique hierarchy in one view | We collapse by default, expand on demand — otherwise the grid exceeds one viewport height |

---

## History

- Originally cells linked to `/techniques/<id>`; moved to popover after usability feedback.
- The `actor=` overlay was added after users kept switching between `/groups/<id>` (group profile) and the bare matrix to do the same thing mentally. Now it's one URL.
- Multi-actor compare (`actor=G0016,G0032`) followed from the actor-overlay feature.

---

## Cross-refs

- Group profile → Matrix: `/groups/<id>` has a "Show on Matrix" button
- Matrix deep link from any 360 map: "Matrix ↗" button in the tab bar
- [`docs/menu/360-views.md`](360-views.md) — the sibling landing page
