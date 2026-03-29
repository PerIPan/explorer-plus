/** Base fields shared by every MITRE ATT&CK entity. */
export interface BaseEntity {
  id: string;
  attackId: string;
  stixId: string;
  name: string;
  description: string | null;
  url: string | null;
  isRevoked: boolean;
  isDeprecated: boolean;
  domain: string | null;
  stixCreated: string;
  stixModified: string;
}

export interface SubTechnique extends BaseEntity {
  tactics: string[];
  platforms: string[] | null;
  detection: string | null;
  maturity: string | null;
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
  maturity: string | null;
  atlasXrefs?: Array<{ attackId: string; name: string; domain: string | null }>;
  sub_techniques: SubTechnique[];
  /** Relationship data returned by the detail endpoint */
  groups?: TechniqueRelatedGroup[];
  software?: TechniqueRelatedSoftware[];
  mitigations?: TechniqueRelatedMitigation[];
  dataComponents?: TechniqueDataComponent[];
  campaigns?: TechniqueRelatedCampaign[];
  /** Framework mapping data (returned by frameworks/technique endpoint) */
  verisCategories?: VerisMapping[];
  cloudControls?: CloudControl[];
}

// ── Group detail relationship sub-types ───────────────────────────────────────

export interface GroupTechnique {
  attackId: string;
  name: string;
  procedure: string | null;
  platforms: string[] | null;
}

export interface GroupSoftware {
  attackId: string;
  name: string;
  type: string;
  description: string | null;
}

export interface GroupCampaign {
  attackId: string;
  name: string;
  description: string | null;
  firstSeen: string | null;
  lastSeen: string | null;
}

export interface GroupSector {
  name: string;
  slug: string | null;
}

export interface Group extends BaseEntity {
  aliases: string[] | null;
  /** Present on detail endpoint */
  techniques?: GroupTechnique[];
  software?: GroupSoftware[];
  campaigns?: GroupCampaign[];
  sectors?: GroupSector[];
  targetedApps?: Array<{ normalized: string; vendor: string; product: string; cveCount: number }>;
}

// ── Campaign detail relationship sub-types ────────────────────────────────────

export interface CampaignTechnique {
  attackId: string;
  name: string;
  description: string | null;
  platforms: string[] | null;
}

export interface CampaignGroup {
  attackId: string;
  name: string;
  description: string | null;
}

export interface CampaignSoftware {
  attackId: string;
  name: string;
  type: string;
  description: string | null;
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
  /** Present on detail endpoint */
  techniques?: CampaignTechnique[];
  software?: CampaignSoftware[];
  groups?: CampaignGroup[];
}

export interface DataComponent {
  id: string;
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
  id: string;
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
  id: string;
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
  /** ATT&CK ID of the tactic (e.g. "TA0001") — used for click navigation. */
  tacticId: string;
  count: number;
  domain: string | null;
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

export interface AttackVersionMeta {
  attackVersion: string;
  domain: string;
  seededAt: string;
}

export interface TopTechnique {
  attackId: string;
  name: string;
  groupCount: number;
}

export interface DashboardData {
  stats: DashboardStats;
  topGroups: TopGroup[];
  topTechniques: TopTechnique[];
  tacticDistribution: TacticDistribution[];
  sectorBreakdown: SectorBreakdown[];
  /** ATT&CK version metadata from seed_metadata. Null if not yet seeded. */
  attackVersion: AttackVersionMeta | null;
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

// ── Framework Types ────────────────────────────────────────────────────────────

export interface NistControl {
  controlId: string;
  controlName: string | null;
  controlFamily: string | null;
  attackTechniqueId: string;
  mappingType: string | null;
}

export interface NistControlSummary {
  controlId: string;
  controlName: string | null;
  controlFamily: string | null;
  techniqueCount: number;
}

export interface EngageMapping {
  engageId: string;
  engageName: string;
  engageDescription: string | null;
  goal: string | null;
  approach: string | null;
  attackTechniqueId: string;
}

export interface EngageSummary {
  engageId: string;
  engageName: string;
  engageDescription: string | null;
  goal: string | null;
  approach: string | null;
  techniqueCount: number;
}

export interface ReactAction {
  actionId: string;
  title: string;
  description: string | null;
  stage: string | null;
  workflow: string | null;
}

export interface VerisMapping {
  verisId: string;
}

export interface CloudControl {
  provider: string;
  controlId: string;
  controlName: string;
  controlDescription?: string | null;
  mappingType?: string | null;
}

export interface FrameworkData {
  attackId: string;
  nist: NistControl[];
  engage: EngageMapping[];
  verisCategories?: VerisMapping[];
  cloudControls?: CloudControl[];
}

// ── CTI Feed Types ─────────────────────────────────────────────────────────────

export interface ThreatReport {
  id: string;
  title: string;
  url: string;
  source: string;
  published_at: string | null;
  created_at: string;
  technique_count: number;
}

export interface IocEntry {
  id: string;
  type: string;
  value: string;
  source: string;
  malware_family: string | null;
  description: string | null;
  source_ref: string | null;
  first_seen_at: string | null;
  created_at: string;
  technique_count?: number;
}

export interface SigmaRule {
  id: string;
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
  id: string;
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

export interface ExternalActor {
  id: string;
  name: string;
  description: string | null;
  source: string;
  country: string | null;
  category: string | null;
  synonyms: string[] | null;
  refs: string[] | null;
  mitreGroupId: string | null;
  mitreGroupName: string | null;
  motivation: string | null;
  firstSeen: string | null;
  suspectedVictims: string[] | null;
  targetCategories: string[] | null;
  suspectedStateSponsor: string | null;
  attributionConfidence: string | null;
}

export interface TechniqueIntelligence {
  attackId: string;
  reports: Array<{
    id: string;
    title: string;
    url: string | null;
    source: string;
    published_at: string | null;
    technique_count: number;
  }>;
  sigmaRules: Array<{
    id: string;
    sigma_id: string;
    title: string;
    level: string | null;
    status: string | null;
    logsource_category: string | null;
    logsource_product: string | null;
  }>;
  atomicTests: Array<{
    id: string;
    test_number: number;
    name: string;
    description: string | null;
    platforms: string[] | null;
    executor_type: string | null;
  }>;
  defensiveMappings: Array<{
    id: string;
    d3fend_id: string;
    d3fend_label: string | null;
    d3fend_tactic: string | null;
  }>;
  iocs: Array<{
    id: string;
    type: string;
    value: string;
    source: string;
    malware_family: string | null;
    description: string | null;
    first_seen_at: string | null;
    confidence: string | null;
    vt_malicious: number | null;
    vt_total: number | null;
    vt_verdict: string | null;
    vt_file_type: string | null;
    cvss_severity: string | null;
  }>;
  detectionStrategies: Array<{
    det_id: string;
    name: string;
    analytics: Array<{
      analytic_id: string;
      name: string;
      description: string | null;
      platforms: string[];
    }>;
  }>;
  cves: Array<{
    cve_id: string;
    description: string | null;
    cvss_severity: string | null;
    published_at: string | null;
    is_kev: boolean;
  }>;
  affectedApps: Array<{
    normalized: string;
    vendor: string;
    product: string;
    cveCount: number;
  }>;
}

// ── CVE Types ─────────────────────────────────────────────────────────────────

export interface CveEntry {
  cveId: string;
  description: string | null;
  cvssScore: number | null;
  cvssSeverity: string | null;
  cweId: string | null;
  publishedAt: string | null;
  sources: string[];
  techniqueCount: number;
  techniques: string[];
  applications: string;
}

export interface CveDetail extends Omit<CveEntry, 'sources' | 'techniqueCount' | 'techniques'> {
  cvssVector: string | null;
  cwes: string[];
  isKev: boolean;
  sources: Array<{ source: string; sourceRef: string | null }>;
  techniques: Array<{ attackId: string; name: string; tactics: string[]; sources: string[] }>;
  affectedApps: Array<{ normalized: string; vendor: string; product: string; versionStart: string | null; versionEnd: string | null; cveCount: number }>;
  reports: Array<{ id: string; title: string; url: string | null; source: string | null; publishedAt: string | null }>;
}
