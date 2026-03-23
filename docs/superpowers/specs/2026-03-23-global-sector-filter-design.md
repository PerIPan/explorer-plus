# Global Sector Filter

## Summary
Dropdown in top nav bar filters the entire app by industry sector (e.g., Healthcare, Finance). Chains through `group_sectors` to narrow Groups, Techniques, Software, Campaigns, Tactics, and the Relationships Explorer.

## UI
- Compact dropdown in top nav bar, right side (next to `?` button)
- Default: "All Sectors" (no filter)
- Options show group count: "Healthcare (23)", "Government (78)"
- Active filter shows visual indicator (badge/highlight)
- URL param `?sector=X` — shareable, bookmarkable
- Persists across page navigation

## State
- `SectorContext` wraps the app, provides `{ sector, setSector }`
- Reads/writes `sector` URL query param
- `useSector()` hook returns `{ sector, sectorParam }` for API calls

## Filtered pages (via group_sectors chain)
- **Groups** — direct: `JOIN group_sectors`
- **Techniques** — `group_techniques → group_sectors`
- **Software** — `group_software → group_sectors`
- **Campaigns** — `group_campaigns → group_sectors`
- **Tactics** — `technique_tactics → group_techniques → group_sectors`
- **Relationships Explorer** — pass sector to relationships API

## Not filtered
- **Frameworks**: NIST 800-53, Engage, RE&CT, Sigma Rules
- **CTI**: Reports, IOCs, Feed Status
- **Extended Intel**: Non-MITRE Actors
- **Other**: Overview/Dashboard, Matrix
- Tooltip on Frameworks + CTI section headers: "Not filtered by sector"

## Sidebar change
- Move Sigma Rules from CTI to Frameworks section

## API changes
Each filterable endpoint gets optional `sector` query param. When present, adds subquery:
```sql
-- Example for techniques
WHERE t.id IN (
  SELECT gt.technique_id FROM group_techniques gt
  JOIN group_sectors gs ON gs.group_id = gt.group_id
  JOIN sectors s ON s.id = gs.sector_id
  WHERE s.slug = $N
)
```

## Sector data
- 12 sectors in DB, 390 group→sector links
- Sectors fetched once via existing `/api/v1/sectors` endpoint
- Cached client-side (staleTime: 1h)

## Edge cases
- No sector param = show all (current behavior)
- Invalid sector slug = ignore, show all
- Pages with Fuse.js search: sector filters server-side data, Fuse filters client-side on top
