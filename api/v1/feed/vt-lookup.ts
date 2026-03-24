import type { VercelRequest, VercelResponse } from '@vercel/node';
import { withHandler } from '../lib/middleware.js';

const VT_BASE = 'https://www.virustotal.com/api/v3';

async function handler(req: VercelRequest, res: VercelResponse): Promise<void> {
  const hash = Array.isArray(req.query.hash) ? req.query.hash[0] : req.query.hash ?? '';

  if (!hash || !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash)) {
    res.status(400).json({ error: 'Invalid hash', code: 'VALIDATION_ERROR' });
    return;
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    res.status(500).json({ error: 'VT_API_KEY not configured', code: 'CONFIG_ERROR' });
    return;
  }

  const headers = { 'x-apikey': apiKey, 'User-Agent': 'mitre-explorer/1.0' };

  try {
    // Fetch file info + behavior in parallel
    const [fileResp, behaviorResp] = await Promise.all([
      fetch(`${VT_BASE}/files/${hash}`, { headers }),
      fetch(`${VT_BASE}/files/${hash}/behaviour_summary`, { headers }),
    ]);

    if (!fileResp.ok) {
      if (fileResp.status === 404) {
        res.status(404).json({ error: 'Hash not found in VirusTotal', code: 'NOT_FOUND' });
        return;
      }
      throw new Error(`VT API error: ${fileResp.status}`);
    }

    const fileData = await fileResp.json();
    const attrs = fileData.data?.attributes ?? {};
    const stats = attrs.last_analysis_stats ?? {};

    // Behavior may 404 if no sandbox ran
    let techniques: Array<{ id: string; severity: string; description: string }> = [];
    let sigmaRules: Array<{ title: string; level: string }> = [];
    let dnsLookups = 0;
    let ipTraffic = 0;

    if (behaviorResp.ok) {
      const behaviorData = await behaviorResp.json();
      const bData = behaviorData.data ?? {};

      techniques = (bData.mitre_attack_techniques ?? []).map((t: Record<string, string>) => ({
        id: t.id ?? '',
        severity: t.severity ?? '',
        description: t.signature_description ?? '',
      }));

      sigmaRules = (bData.sigma_analysis_results ?? []).map((s: Record<string, string>) => ({
        title: s.rule_title ?? '',
        level: s.rule_level ?? '',
      }));

      dnsLookups = (bData.dns_lookups ?? []).length;
      ipTraffic = (bData.ip_traffic ?? []).length;
    }

    // Dedupe techniques by ID, keep highest severity
    const techMap = new Map<string, { id: string; severity: string; description: string }>();
    const severityOrder: Record<string, number> = {
      IMPACT_SEVERITY_HIGH: 4,
      IMPACT_SEVERITY_MEDIUM: 3,
      IMPACT_SEVERITY_LOW: 2,
      IMPACT_SEVERITY_INFO: 1,
    };
    for (const t of techniques) {
      const existing = techMap.get(t.id);
      if (!existing || (severityOrder[t.severity] ?? 0) > (severityOrder[existing.severity] ?? 0)) {
        techMap.set(t.id, t);
      }
    }

    res.status(200).json({
      hash,
      fileName: attrs.meaningful_name ?? null,
      fileType: attrs.type_description ?? null,
      fileSize: attrs.size ?? null,
      tags: (attrs.tags ?? []).slice(0, 10),
      stats: {
        malicious: stats.malicious ?? 0,
        suspicious: stats.suspicious ?? 0,
        harmless: stats.harmless ?? 0,
        undetected: stats.undetected ?? 0,
        total: Object.values(stats).reduce((a: number, b) => a + (b as number), 0),
      },
      sigmaStats: attrs.sigma_analysis_stats ?? null,
      techniques: Array.from(techMap.values()).sort(
        (a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0),
      ),
      sigmaRules: sigmaRules.slice(0, 10),
      network: { dnsLookups, ipTraffic },
    });
  } catch (err) {
    console.error('VT lookup error:', err);
    res.status(500).json({ error: 'VirusTotal lookup failed', code: 'VT_ERROR' });
  }
}

export default withHandler(handler, { cacheTtl: 600 });
