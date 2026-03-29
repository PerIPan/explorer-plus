import type { VercelRequest, VercelResponse } from '@vercel/node';
import { readFileSync } from 'fs';
import { join } from 'path';

export default function handler(_req: VercelRequest, res: VercelResponse) {
  const cardPath = join(process.cwd(), 'public', '.well-known', 'agent-card.json');
  const card = readFileSync(cardPath, 'utf8');
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'public, max-age=3600');
  res.status(200).send(card);
}
