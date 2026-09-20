import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['d3', 'd3-force', 'd3-selection', 'fuse.js'],
  // Next 16.3 writes AGENTS.md + CLAUDE.md into the repo root on every dev
  // run. A generated CLAUDE.md would be read as this project's instructions by
  // coding agents, silently competing with the real ones, so opt out.
  agentRules: false,
};

export default nextConfig;
