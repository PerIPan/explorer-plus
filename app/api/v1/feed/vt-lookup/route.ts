import { NextRequest } from 'next/server';
import { jsonResponse, errorResponse } from '../../../lib/handler';
import { withCors, corsOptions as OPTIONS } from '../../../lib/cors';

export { OPTIONS };

const VT_BASE = 'https://www.virustotal.com/api/v3';

export async function GET(req: NextRequest) {
  const hash = req.nextUrl.searchParams.get('hash') ?? '';

  if (!hash || !/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(hash)) {
    return withCors(errorResponse(400, 'Invalid hash', 'VALIDATION_ERROR'));
  }

  const apiKey = process.env.VT_API_KEY;
  if (!apiKey) {
    return withCors(errorResponse(500, 'VT_API_KEY not configured', 'CONFIG_ERROR'));
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
        return withCors(errorResponse(404, 'Hash not found in VirusTotal', 'NOT_FOUND'));
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

    return withCors(jsonResponse({
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
    }, 600));
  } catch (err) {
    console.error('VT lookup error:', err);
    return withCors(errorResponse(500, 'VirusTotal lookup failed', 'VT_ERROR'));
  }
}
