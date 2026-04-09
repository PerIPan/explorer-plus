import type { NextConfig } from 'next';

const nextConfig: NextConfig = {
  transpilePackages: ['d3', 'd3-force', 'd3-selection', 'fuse.js'],
};

export default nextConfig;
