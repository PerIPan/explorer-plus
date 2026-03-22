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
  tacticPhase: string | null;
  platforms: string[] | null;
  detection: string | null;
}

export interface Technique extends BaseEntity {
  tacticPhase: string | null;
  platforms: string[] | null;
  detection: string | null;
  sub_techniques: SubTechnique[];
}

export interface Group extends BaseEntity {
  aliases: string[] | null;
  country: string | null;
}

export interface Software extends BaseEntity {
  type: 'malware' | 'tool';
  aliases: string[] | null;
  platforms: string[] | null;
}

export interface Campaign extends BaseEntity {
  aliases: string[] | null;
  first_seen: string | null;
  last_seen: string | null;
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
}

export interface Mitigation extends BaseEntity {
  mitigationId: string | null;
}

export interface Tactic extends BaseEntity {
  shortName: string;
  sort_order: number;
}

export interface Sector {
  id: number;
  name: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
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
