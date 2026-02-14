// Core type definitions for AI Compliance Automation System

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ComplianceFramework = 'SOC2' | 'ISO27001' | 'HIPAA' | 'GDPR' | 'PCI-DSS' | 'CUSTOM';
export type ViolationStatus = 'open' | 'investigating' | 'remediating' | 'resolved' | 'false_positive';
export type PolicyStatus = 'active' | 'draft' | 'archived' | 'superseded';

// ============================================================================
// Policy Types
// ============================================================================

export interface Policy {
  id: string;
  name: string;
  description: string;
  framework: ComplianceFramework;
  status: PolicyStatus;
  version: string;
  requirements: PolicyRequirement[];
  controls: Control[];
  metadata: PolicyMetadata;
  content: string;
  parsedAt: Date;
}

export interface PolicyRequirement {
  id: string;
  description: string;
  category: string;
  mandatory: boolean;
  relatedControls: string[];
  severity: SeverityLevel;
}

export interface Control {
  id: string;
  name: string;
  description: string;
  implementation: string;
  tested: boolean;
  lastTested?: Date;
  testResult?: 'pass' | 'fail' | 'not_tested' | undefined;
}

export interface PolicyMetadata {
  owner: string;
  department: string;
  effectiveDate: Date;
  reviewDate: Date;
  tags: string[];
  attachments: string[];
}

// ============================================================================
// Infrastructure Monitor Types
// ============================================================================

export interface MonitoredAsset {
  id: string;
  type: 'domain' | 'ip' | 'certificate' | 'cloud_resource';
  identifier: string;
  organizationId: string;
  lastChecked: Date;
  status: 'active' | 'inactive' | 'unknown';
  metadata: Record<string, unknown>;
}

export interface DomainRecord {
  domain: string;
  registrar: string;
  registrationDate: Date;
  expirationDate: Date;
  nameservers: string[];
  dnsRecords: DNSRecord[];
  status: string[];
}

export interface DNSRecord {
  type: 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA';
  name: string;
  value: string;
  ttl: number;
}

export interface IPRecord {
  ip: string;
  version: 4 | 6;
  asn: number;
  asnOrg: string;
  country: string;
  city: string;
  isp: string;
  isProxy: boolean;
  isVPN: boolean;
  isTor: boolean;
  isPrivate?: boolean;
  hostname?: string;
  reputation: 'good' | 'suspicious' | 'malicious' | 'unknown';
}

export interface CertificateInfo {
  domain: string;
  issuer: string;
  subject: string;
  validFrom: Date;
  validTo: Date;
  serialNumber: string;
  signatureAlgorithm: string;
  keyAlgorithm: string;
  keySize: number;
  isValid: boolean;
  daysUntilExpiry: number;
}

// ============================================================================
// Violation Detection Types
// ============================================================================

export interface Violation {
  id: string;
  policyId: string;
  policyName: string;
  requirementId?: string;
  controlId?: string;
  assetId: string;
  assetType: 'domain' | 'ip' | 'certificate' | 'cloud_resource';
  assetIdentifier: string;
  severity: SeverityLevel;
  status: ViolationStatus;
  title: string;
  description: string;
  detectedAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
  evidence: ViolationEvidence[];
  remediation: RemediationAction[];
}

export interface ViolationEvidence {
  type: 'screenshot' | 'log' | 'api_response' | 'config' | 'certificate' | 'other';
  description: string;
  data: string;
  timestamp: Date;
}

export interface RemediationAction {
  id: string;
  type: 'manual' | 'automated';
  status: 'pending' | 'in_progress' | 'completed' | 'failed';
  description: string;
  assignedTo?: string;
  completedAt?: Date;
  automationScript?: string;
}

export interface DetectionRule {
  id: string;
  name: string;
  description: string;
  condition: RuleCondition;
  severity: SeverityLevel;
  enabled: boolean;
  framework: ComplianceFramework;
}

export interface RuleCondition {
  type: 'domain' | 'ip' | 'certificate' | 'composite';
  assetType: 'domain' | 'ip' | 'certificate';
  operator: 'equals' | 'contains' | 'regex' | 'in' | 'not_in' | 'greater_than' | 'less_than';
  field: string;
  value: string | string[] | number;
}

// ============================================================================
// Agent Memory Types
// ============================================================================

export interface MemoryEntry {
  id: string;
  type: 'policy' | 'violation' | 'incident' | 'conversation' | 'knowledge';
  content: string;
  embedding: number[];
  metadata: MemoryMetadata;
  createdAt: Date;
  accessedAt: Date;
  accessCount: number;
}

export interface MemoryMetadata {
  policyId?: string;
  violationId?: string;
  incidentId?: string;
  tags: string[];
  source: string;
}

export interface ConversationEntry {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: Date;
  context: {
    policies: string[];
    violations: string[];
  };
}

// ============================================================================
// SOAR Automation Types
// ============================================================================

export interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: PlaybookTrigger;
  steps: PlaybookStep[];
  enabled: boolean;
  lastRun?: Date;
}

export interface PlaybookTrigger {
  type: 'violation' | 'schedule' | 'manual' | 'webhook';
  conditions: {
    severity?: SeverityLevel[];
    assetType?: string[];
    policyId?: string;
  };
}

export interface PlaybookStep {
  id: string;
  name: string;
  type: 'action' | 'condition' | 'delay' | 'notification' | 'remediation';
  config: StepConfig;
  onSuccess?: string;
  onFailure?: string;
}

export interface StepConfig {
  action?: 'create_incident' | 'send_alert' | 'run_script' | 'update_status' | 'assign' | 'escalate';
  notification?: {
    channel: 'slack' | 'email' | 'jira' | 'pagerduty' | 'webhook';
    template: string;
    recipients: string[];
  };
  remediation?: {
    script: string;
    parameters: Record<string, string>;
  };
  condition?: {
    field: string;
    operator: string;
    value: unknown;
  };
  delay?: {
    seconds: number;
  };
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  status: 'open' | 'investigating' | 'mitigated' | 'closed';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  assignee?: string;
  reporter: string;
  violationIds: string[];
  timeline: IncidentEvent[];
  createdAt: Date;
  updatedAt: Date;
  resolvedAt?: Date;
}

export interface IncidentEvent {
  id: string;
  type: 'created' | 'updated' | 'comment' | 'status_change' | 'assignment' | 'escalation';
  description: string;
  actor: string;
  timestamp: Date;
  data?: Record<string, unknown>;
}

// ============================================================================
// Report Types
// ============================================================================

export interface ComplianceReport {
  id: string;
  framework: ComplianceFramework;
  type: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
  period: {
    start: Date;
    end: Date;
  };
  summary: ReportSummary;
  findings: ReportFinding[];
  controls: ControlStatus[];
  evidence: EvidenceItem[];
  generatedAt: Date;
  generatedBy: string;
}

export interface ReportSummary {
  totalControls: number;
  compliantControls: number;
  nonCompliantControls: number;
  notApplicableControls: number;
  compliancePercentage: number;
  criticalFindings: number;
  highFindings: number;
  mediumFindings: number;
  riskScore: number;
  trend: 'improving' | 'stable' | 'degrading';
}

export interface ReportFinding {
  id: string;
  title: string;
  description: string;
  severity: SeverityLevel;
  controlId: string;
  recommendation: string;
  evidence: string[];
}

export interface ControlStatus {
  controlId: string;
  name: string;
  status: 'compliant' | 'non_compliant' | 'not_applicable' | 'not_tested';
  lastTested?: Date;
  testResult?: 'pass' | 'fail';
  findings: string[];
}

export interface EvidenceItem {
  id: string;
  controlId: string;
  type: 'screenshot' | 'log' | 'config' | 'certificate' | 'document';
  description: string;
  collectedAt: Date;
  data: string;
}

// ============================================================================
// Configuration Types
// ============================================================================

export interface AgentConfig {
  organization: {
    id: string;
    name: string;
    framework: ComplianceFramework;
  };
  monitoring: {
    dnsCheckInterval: number;
    ipCheckInterval: number;
    certCheckInterval: number;
  };
  notifications: {
    slack?: SlackConfig;
    jira?: JiraConfig;
    pagerduty?: PagerDutyConfig;
    email?: EmailConfig;
  };
  storage: {
    type: 'sqlite' | 'postgres';
    connectionString: string;
  };
}

export interface SlackConfig {
  webhookUrl: string;
  channel: string;
  botToken?: string;
}

export interface JiraConfig {
  baseUrl: string;
  apiToken: string;
  email: string;
  projectKey: string;
}

export interface PagerDutyConfig {
  apiKey: string;
  serviceId: string;
}

export interface EmailConfig {
  smtpHost: string;
  smtpPort: number;
  username: string;
  password: string;
  from: string;
  to: string[];
}
