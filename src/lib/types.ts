/** Base fields shared by every MITRE ATT&CK entity. */
export interface BaseEntity {
  id: number;
  attackId: string;
  stixId: string;
  name: string;
  description: string | null;
  url: string | null;
  isRevoked: boolean;
  isDeprecated: boolean;
  stixCreated: string;
  stixModified: string;
}

export interface SubTechnique extends BaseEntity {
  tactics: string[];
  platforms: string[] | null;
  detection: string | null;
}

export interface TechniqueRelatedGroup {
  attackId: string;
  name: string;
  procedure: string | null;
}

export interface TechniqueRelatedSoftware {
  attackId: string;
  name: string;
  type: string;
  description: string | null;
}

export interface TechniqueRelatedMitigation {
  attackId: string;
  name: string;
  description: string | null;
}

export interface TechniqueDataComponent {
  componentName: string;
  description: string | null;
  dataSourceName: string;
  dataSourceAttackId: string;
}

export interface TechniqueRelatedCampaign {
  attackId: string;
  name: string;
  description: string | null;
}

export interface Technique extends BaseEntity {
  tactics: string[];
  platforms: string[] | null;
  detection: string | null;
  sub_techniques: SubTechnique[];
  /** Relationship data returned by the detail endpoint */
  groups?: TechniqueRelatedGroup[];
  software?: TechniqueRelatedSoftware[];
  mitigations?: TechniqueRelatedMitigation[];
  dataComponents?: TechniqueDataComponent[];
  campaigns?: TechniqueRelatedCampaign[];
}

export interface Group extends BaseEntity {
  aliases: string[] | null;
}

export interface Software extends BaseEntity {
  type: 'malware' | 'tool';
  aliases: string[] | null;
  platforms: string[] | null;
}

export interface Campaign extends BaseEntity {
  aliases: string[] | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface DataComponent {
  id: number;
  name: string;
  description: string | null;
  dataSourceId: number;
}

export interface DataSource extends BaseEntity {
  platforms: string[] | null;
  components: DataComponent[];
  componentCount?: number;
}

export interface Mitigation extends BaseEntity {
}

export interface Tactic extends BaseEntity {
  sortOrder: number | null;
  techniques?: Array<{ attackId: string; name: string; description?: string | null }>;
}

export interface Sector {
  id: number;
  name: string;
  slug: string | null;
  groupCount: number;
}

export interface Pagination {
  page: number;
  limit: number;
  total: number;
  totalPages: number;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: Pagination;
}

export interface ErrorResponse {
  error: string;
  code: string;
}

export interface SearchResponse {
  techniques: Technique[];
  groups: Group[];
  software: Software[];
  mitigations: Mitigation[];
  campaigns: Campaign[];
  data_sources: DataSource[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  attackId?: string;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface GraphData {
  center: GraphNode;
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
}

export interface MatrixTechniqueCell {
  id: number;
  attackId: string;
  name: string;
  subTechniques: Array<{ attackId: string; name: string }>;
}

export interface MatrixColumn {
  tactic: Tactic;
  techniques: MatrixTechniqueCell[];
}

export type MatrixData = MatrixColumn[];

export interface TacticDistribution {
  tacticName: string;
  count: number;
}

export interface SectorBreakdown {
  sectorName: string;
  groupCount: number;
}

export interface TopGroup {
  attackId: string;
  name: string;
  techniqueCount: number;
}

export interface DashboardStats {
  techniqueCount: number;
  groupCount: number;
  softwareCount: number;
  mitigationCount: number;
  campaignCount: number;
  dataSourceCount: number;
}

export interface DashboardData {
  stats: DashboardStats;
  topGroups: TopGroup[];
  tacticDistribution: TacticDistribution[];
  sectorBreakdown: SectorBreakdown[];
}

/** Entity types used for routing and entity links. */
export type EntityType =
  | 'technique'
  | 'group'
  | 'software'
  | 'campaign'
  | 'mitigation'
  | 'data_source'
  | 'tactic';

// ── CTI Feed Types ─────────────────────────────────────────────────────────────

export interface ThreatReport {
  id: number;
  title: string;
  url: string;
  source: string;
  published_at: string | null;
  created_at: string;
  technique_count: number;
}

export interface IocEntry {
  id: number;
  type: string;
  value: string;
  source: string;
  malware_family: string | null;
  first_seen_at: string | null;
  created_at: string;
}

export interface SigmaRule {
  id: number;
  sigma_id: string;
  title: string;
  level: string | null;
  status: string | null;
  logsource_category: string | null;
  logsource_product: string | null;
  technique_attack_id: string | null;
  technique_name: string | null;
  created_at: string;
}

export interface AtomicTest {
  id: number;
  test_number: number;
  name: string;
  description: string | null;
  platforms: string[] | null;
  executor_type: string | null;
  executor_command: string | null;
  cleanup_command: string | null;
  technique_attack_id: string | null;
  technique_name: string | null;
}

export interface FeedSyncStatus {
  source: string;
  lastSync: string;
  status: 'running' | 'success' | 'error';
  recordsInserted: number;
  recordsSkipped: number;
  error: string | null;
  metadata: Record<string, unknown> | null;
}

export interface TechniqueIntelligence {
  attackId: string;
  reports: Array<{
    id: number;
    title: string;
    url: string;
    source: string;
    published_at: string | null;
  }>;
  sigmaRules: Array<{
    id: number;
    sigma_id: string;
    title: string;
    level: string | null;
    status: string | null;
    logsource_category: string | null;
    logsource_product: string | null;
  }>;
  atomicTests: Array<{
    id: number;
    test_number: number;
    name: string;
    description: string | null;
    platforms: string[] | null;
    executor_type: string | null;
  }>;
  defensiveMappings: Array<{
    id: number;
    d3fend_id: string;
    d3fend_label: string;
    d3fend_description: string | null;
  }>;
  iocs: Array<{
    id: number;
    type: string;
    value: string;
    source: string;
    malware_family: string | null;
    first_seen_at: string | null;
    confidence: string | null;
  }>;
}
