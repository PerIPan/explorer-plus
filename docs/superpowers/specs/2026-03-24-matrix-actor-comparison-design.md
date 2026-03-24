# Matrix Threat Actor Comparison

**Date:** 2026-03-24
**Status:** Approved

## Overview

Add ability to select up to 3 threat actors on the Matrix page. Each actor's techniques are color-coded on the matrix grid. Techniques shared by 2+ actors keep the default teal. Techniques not used by any selected actor are hidden (not rendered).

## User Flow

1. User opens `/matrix`
2. Default view unchanged (teal heatmap)
3. User types in actor search dropdown (top-right controls bar)
4. Selects up to 3 actors — each gets a colored chip (orange, purple, pink)
5. Matrix re-colors: unique techniques get actor color, shared stay teal, unused hidden
6. Legend strip shows actor name + color swatch + technique count
7. User can dismiss actors via chip x-button; matrix reverts when all removed

## Actor Selector UI

- Search input with type-ahead, filters groups by name and aliases
- Uses existing `useFuseFilter` hook with keys: `['name', 'aliases']`
- Respects global sector filter: when a sector is selected, only show groups that target that sector (use `sector` param on groups API)
- Chips rendered inline showing selected actor name + color dot + dismiss button
- When 3 actors selected, input is disabled with placeholder "Max 3 actors"
- Placed top-right of the controls bar (right side, after existing filter + legend)
- Revoked/deprecated groups excluded (default API behavior)
- Keyboard: arrow keys navigate suggestions, Enter selects, Backspace removes last chip, Escape closes dropdown

## Color Scheme

Use CSS variables directly — no hardcoded RGBA. Resolve actual RGB values at render time via `getComputedStyle`.

| Actor Slot | Color | CSS Variable |
|---|---|---|
| 1 | Orange | `--accent-orange` |
| 2 | Purple | `--accent-purple` |
| 3 | Pink | `--accent-pink` |
| Shared (2+) | Default teal | existing heatmap |

## Matrix Coloring Logic

When actors are selected:

```
for each cell in matrix:
  actors_using = [actor for actor in selected if cell.attackId in actor.parentTechniques]

  if len(actors_using) == 0:
    cell.hidden = true  (not rendered)
  elif len(actors_using) == 1:
    cell.color = actors_using[0].color
    cell.opacity = 0.55  (flat, no heatmap scaling)
  elif len(actors_using) >= 2:
    cell.color = default teal
    cell.opacity = existing heatmap logic
```

**Sub-technique normalization:** Group technique lists include sub-techniques (e.g. T1059.001). The lookup map must normalize to parent IDs via `attackId.split('.')[0]` since the matrix only renders parent techniques.

**Text filter interaction:** Both filters compute a single combined state per cell — no stacked CSS opacity. The cell computes one final style:
- If text filter active AND cell doesn't match text → hidden, regardless of actor
- If text filter matches (or inactive) AND actor mode active → apply actor coloring logic above (hide if unused)
- If no actors selected → existing text filter behavior unchanged

## Legend Strip

Below the selector, a horizontal strip:

```
[orange dot] APT29 (47 techniques)  [purple dot] Lazarus (62 techniques)  [pink dot] APT28 (55 techniques)
```

Count = unique parent technique IDs from the actor's technique list that have a corresponding cell in the current matrix view.

## Data Flow

1. **Actor search:** Use existing `useGroups({ limit: '5000', ...sectorParam })` — sector param from `useSector()` context. Client-side filter via `useFuseFilter` with keys `['name', 'aliases']`
2. **Technique lookup:** Use `useQueries` from `@tanstack/react-query` to fetch 0-3 group details in parallel. Each query calls the group detail endpoint. `useQueries` handles variable query count without violating React hook rules.
3. **Build lookup:** `Map<string, Set<number>>` — parent technique attackId → set of actor slot indices (0, 1, 2). Normalize sub-techniques: `attackId.split('.')[0]`
4. **Pass to grid:** New prop on `MatrixGrid`: `actorOverlay?: ActorOverlay`
5. **Cell rendering:** `MatrixCell` receives resolved overlay state

### ActorOverlay type

```typescript
interface ActorOverlay {
  /** CSS variable names for each actor slot */
  colors: string[];
  /** parentAttackId → set of actor slot indices */
  lookup: Map<string, Set<number>>;
}
```

### MatrixCell overlay prop

```typescript
interface CellOverlay {
  /** Resolved background color string, or null if dimmed */
  color: string | null;
  /** 'single' = flat actor color, 'shared' = default heatmap, 'hidden' = not used (don't render) */
  mode: 'single' | 'shared' | 'hidden';
}
```

`MatrixGrid` resolves the lookup into a `CellOverlay` per cell before passing to `MatrixCell`. This keeps `MatrixCell` simple — it just applies the resolved style.

## Component Changes

### `Matrix.tsx`
- Add state: `selectedActors: Array<{ attackId: string; name: string }>` (max 3)
- Add `useQueries` for fetching selected group details
- Build technique lookup map from fetched group data (normalize sub-techniques)
- Pass `actorOverlay` prop to `MatrixGrid`
- Render legend strip when actors selected

### `MatrixActorSelector.tsx` (new file)
- Type-ahead search input with chip rendering
- Props: `groups`, `selected`, `onSelect`, `onRemove`, `maxActors`
- ~80-100 lines, cleaner than inlining in Matrix.tsx

### `MatrixGrid.tsx`
- Accept optional `actorOverlay` prop
- Resolve overlay per cell: lookup attackId → determine mode (single/shared/hidden)
- Combine with text filter: hidden cells not rendered at all
- Pass `CellOverlay` to each `MatrixCell`

### `MatrixCell.tsx`
- Accept optional `overlay?: CellOverlay` prop
- When `overlay` provided: use `overlay.color` and `overlay.mode` for background
- When `overlay.mode === 'hidden'`: don't render the cell
- When `overlay.mode === 'single'`: flat opacity 0.55 with actor color
- When `overlay.mode === 'shared'`: existing heatmap logic with default teal
- When no overlay: existing behavior unchanged

## Edge Cases

- Actor with 0 techniques in the matrix → show in legend with "(0 techniques)", no cells colored
- Same technique mapped to 2+ actors → default teal, counted in each actor's legend
- Removing last actor → revert to default heatmap
- Group data loading → show spinner on chip until techniques loaded
- Sub-technique T1059.001 normalizes to parent T1059 in lookup

## Performance

- Max 3 concurrent group detail fetches (react-query caches after first load)
- Lookup map is O(n) to build, O(1) per cell lookup
- `useQueries` avoids conditional hook calls
- No additional API endpoints needed
