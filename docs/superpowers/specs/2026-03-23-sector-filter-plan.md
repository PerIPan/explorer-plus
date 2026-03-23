# Global Sector Filter — Implementation Plan

## Phase 1: Foundation (context + hook + dropdown)
1. Create `src/contexts/SectorContext.tsx` — React context with `sector`/`setSector`, reads/writes `?sector=` URL param
2. Create `src/hooks/useSector.ts` — convenience hook returning `{ sector, sectorParam }`
3. Wrap app in `SectorProvider` in `App.tsx`
4. Create `SectorDropdown` component in `src/components/layout/SectorDropdown.tsx` — fetches sectors from API, shows "All Sectors" + "Name (count)", updates context
5. Add `SectorDropdown` to the top nav bar (right side, next to `?`)
6. Move Sigma from CTI to Frameworks in `Sidebar.tsx`
7. Add "Not filtered by sector" tooltip to Frameworks + CTI section headers

## Phase 2: API endpoints (add sector param)
8. `api/v1/groups/index.ts` — add optional `sector` param, filter via `JOIN group_sectors`
9. `api/v1/techniques/index.ts` — filter via `group_techniques → group_sectors` subquery
10. `api/v1/software/index.ts` — filter via `group_software → group_sectors` subquery
11. `api/v1/campaigns/index.ts` — filter via `group_campaigns → group_sectors` subquery
12. `api/v1/tactics/index.ts` — filter via `technique_tactics → group_techniques → group_sectors` subquery
13. `api/v1/relationships/[attackId].ts` — pass sector filter to relationship queries

## Phase 3: Frontend pages (wire up sector param)
14. `GroupsList.tsx` — add `sectorParam` to API params
15. `TechniquesList.tsx` — add `sectorParam` to API params
16. `SoftwareList.tsx` — add `sectorParam` to API params
17. `CampaignsList.tsx` — add `sectorParam` to API params
18. `TacticsList.tsx` — add `sectorParam` to API params (if it uses API)
19. `Relationships.tsx` — pass sector to `useRelationships` hook

## Phase 4: Polish
20. Visual indicator when sector filter is active (badge on dropdown)
21. Verify Fuse.js search works correctly on top of sector-filtered data
22. Test edge cases: invalid sector slug, empty results, switching sectors
23. Compile check + review agents + push

## Files touched
- New: `SectorContext.tsx`, `useSector.ts`, `SectorDropdown.tsx`
- Modified: `App.tsx`, `Sidebar.tsx`, 6 API endpoints, 6 page components, `useApi.ts`
