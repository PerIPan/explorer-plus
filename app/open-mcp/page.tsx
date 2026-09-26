import type { Metadata } from 'next';
import { OpenMcp } from '../../src/views/OpenMcp';
import { AGENT_TOOL_COUNT } from '../../src/lib/site';

export const metadata: Metadata = {
  title: 'Open MCP — anonymous MCP server for ATT&CK, CVEs and advisories',
  description:
    `An anonymous, unmetered Model Context Protocol server: ${AGENT_TOOL_COUNT} tools over Streamable HTTP for ATT&CK, ` +
    `CVEs, CAPEC, GHSA/OSV advisories, compliance frameworks and the ICS Purdue model. Also reachable over A2A. No key required.`,
  alternates: { canonical: '/open-mcp' },
};

export default function Page() {
  return <OpenMcp />;
}
