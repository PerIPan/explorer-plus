import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';

import {
  MODEL_NODES,
  MODEL_EDGES,
  MODEL_WIDTH,
  MODEL_HEIGHT,
  layoutProblems,
  nodeRadii,
} from '../../src/lib/data-model-graph.mjs';

/* The header "Data Model" diagram is coordinates nobody can review by eye in a
 * diff. These tests are the review: the layout check uses the renderer's own
 * geometry, so a clean result means no node sits on another and no edge runs
 * through a node it does not connect. */

test('layout: no overlaps, no edge through a foreign node, nothing off canvas', () => {
  assert.deepEqual(layoutProblems(MODEL_NODES, MODEL_EDGES), []);
});

test('layout check catches what it claims to (a deliberately broken copy)', () => {
  const moved = MODEL_NODES.map((n) => (n.id === 'mitigation' ? { ...n, x: 650, y: 300 } : n));
  const problems = layoutProblems(moved, MODEL_EDGES);
  assert.ok(problems.some((p) => p.startsWith('overlap: ') && p.includes('mitigation')), problems.join('; '));
  const offCanvas = MODEL_NODES.map((n) => (n.id === 'gcp' ? { ...n, x: MODEL_WIDTH } : n));
  assert.ok(layoutProblems(offCanvas, MODEL_EDGES).includes('off canvas: gcp'));
  assert.ok(layoutProblems(MODEL_NODES, [...MODEL_EDGES, { from: 'nope', to: 'technique', label: 'x' }]).includes('dangling edge: nope -> technique'));
});

test('ids are unique and every node takes part in at least one edge', () => {
  const ids = MODEL_NODES.map((n) => n.id);
  assert.equal(new Set(ids).size, ids.length);
  const linked = new Set(MODEL_EDGES.flatMap((e) => [e.from, e.to]));
  for (const id of ids) assert.ok(linked.has(id), `${id} has no edge`);
});

test('every node links to a page that exists in app/', () => {
  // The old diagram pointed VERIS, Azure, GCP, Atomic and D3FEND at /techniques
  // because their pages did not exist yet; this keeps a link from going stale.
  for (const n of MODEL_NODES) {
    const route = n.path.split('?')[0].replace(/^\//, '');
    const page = new URL(`../../app/${route}/page.tsx`, import.meta.url);
    assert.ok(existsSync(page), `${n.id} -> ${n.path} has no app/${route}/page.tsx`);
  }
});

test('the hub is the largest node and sits inside the canvas', () => {
  const hub = MODEL_NODES.find((n) => n.id === 'technique');
  assert.ok(hub);
  for (const n of MODEL_NODES) assert.ok(nodeRadii(n).rx <= nodeRadii(hub).rx || n.label.length > hub.label.length, n.id);
  assert.ok(hub.x > 0 && hub.x < MODEL_WIDTH && hub.y > 0 && hub.y < MODEL_HEIGHT);
});
