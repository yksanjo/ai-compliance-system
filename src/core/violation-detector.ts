import { v4 as uuidv4 } from 'uuid';
import {
  Violation,
  ViolationEvidence,
  RemediationAction,
  DetectionRule,
  Policy,
  SeverityLevel,
  ViolationStatus,
  DomainRecord,
  IPRecord,
  CertificateInfo,
  ComplianceFramework
} from '../types/index.js';
import { InfrastructureMonitor } from './infrastructure-monitor.js';

export class ViolationDetector {
  private violations: Map<string, Violation> = new Map();
  private rules: DetectionRule[] = [];
  private monitor: InfrastructureMonitor;

  constructor(monitor: InfrastructureMonitor) {
    this.monitor = monitor;
    this.initializeDefaultRules();
  }

  /**
   * Initialize default detection rules
   */
  private initializeDefaultRules(): void {
    this.rules = [
      // Certificate expiration rules
      {
        id: 'cert-expiry-critical',
        name: 'Certificate Expiring Within 7 Days',
        description: 'SSL/TLS certificate will expire within 7 days - critical',
        condition: {
          type: 'certificate',
          assetType: 'certificate',
          operator: 'less_than',
          field: 'daysUntilExpiry',
          value: 7
        },
        severity: 'critical',
        enabled: true,
        framework: 'CUSTOM'
      },
      {
        id: 'cert-expiry-high',
        name: 'Certificate Expiring Within 30 Days',
        description: 'SSL/TLS certificate will expire within 30 days',
        condition: {
          type: 'certificate',
          assetType: 'certificate',
          operator: 'less_than',
          field: 'daysUntilExpiry',
          value: 30
        },
        severity: 'high',
        enabled: true,
        framework: 'CUSTOM'
      },
      {
        id: 'cert-expiry-medium',
        name: 'Certificate Expiring Within 60 Days',
        description: 'SSL/TLS certificate will expire within 60 days',
        condition: {
          type: 'certificate',
          assetType: 'certificate',
          operator: 'less_than',
          field: 'daysUntilExpiry',
          value: 60
        },
        severity: 'medium',
        enabled: true,
        framework: 'CUSTOM'
      },
      // Domain security rules
      {
        id: 'domain-missing-spf',
        name: 'Domain Missing SPF Record',
        description: 'Domain is missing SPF record - email spoofing risk',
        condition: {
          type: 'domain',
          assetType: 'domain',
          operator: 'not_in',
          field: 'security',
          value: ['spf']
        },
        severity: 'high',
        enabled: true,
        framework: 'CUSTOM'
      },
      {
        id: 'domain-missing-dmarc',
        name: 'Domain Missing DMARC Record',
        description: 'Domain is missing DMARC record - email spoofing risk',
        condition: {
          type: 'domain',
          assetType: 'domain',
          operator: 'not_in',
          field: 'security',
          value: ['dmarc']
        },
        severity: 'high',
        enabled: true,
        framework: 'CUSTOM'
      },
      // IP reputation rules
      {
        id: 'ip-malicious',
        name: 'Malicious IP Address',
        description: 'IP address has malicious reputation',
        condition: {
          type: 'ip',
          assetType: 'ip',
          operator: 'equals',
          field: 'reputation',
          value: 'malicious'
        },
        severity: 'critical',
        enabled: true,
        framework: 'CUSTOM'
      },
      {
        id: 'ip-suspicious',
        name: 'Suspicious IP Address',
        description: 'IP address has suspicious reputation',
        condition: {
          type: 'ip',
          assetType: 'ip',
          operator: 'equals',
          field: 'reputation',
          value: 'suspicious'
        },
        severity: 'high',
        enabled: true,
        framework: 'CUSTOM'
      },
      {
        id: 'ip-tor-exit',
        name: 'Tor Exit Node',
        description: 'IP address is a known Tor exit node',
        condition: {
          type: 'ip',
          assetType: 'ip',
          operator: 'equals',
          field: 'isTor',
          value: 'true'
        },
        severity: 'high',
        enabled: true,
        framework: 'CUSTOM'
      }
    ];
  }

  /**
   * Check all monitored assets against detection rules
   */
  async runDetection(policies: Policy[]): Promise<Violation[]> {
    const detectedViolations: Violation[] = [];
    const assets = this.monitor.getAssets();

    for (const asset of assets) {
      const violations = await this.checkAsset(asset.identifier, asset.type, policies);
      detectedViolations.push(...violations);
    }

    return detectedViolations;
  }

  /**
   * Check a specific asset for violations
   */
  async checkAsset(identifier: string, type: 'domain' | 'ip' | 'certificate' | 'cloud_resource', policies: Policy[]): Promise<Violation[]> {
    const violations: Violation[] = [];

    // Skip cloud_resource for now
    if (type === 'cloud_resource') {
      return violations;
    }

    if (type === 'certificate') {
      const certInfo = this.monitor.getCertificateInfo(identifier);
      if (certInfo) {
        const certViolations = this.checkCertificate(certInfo, policies);
        violations.push(...certViolations);
      }
    } else if (type === 'domain') {
      const domainInfo = this.monitor.getDomainInfo(identifier);
      if (domainInfo) {
        const domainViolations = this.checkDomain(domainInfo, policies);
        violations.push(...domainViolations);
      }
    } else if (type === 'ip') {
      const ipInfo = this.monitor.getIPInfo(identifier);
      if (ipInfo) {
        const ipViolations = this.checkIP(ipInfo, policies);
        violations.push(...ipViolations);
      }
    }

    // Store violations
    for (const violation of violations) {
      this.violations.set(violation.id, violation);
    }

    return violations;
  }

  /**
   * Check certificate for violations
   */
  private checkCertificate(cert: CertificateInfo, policies: Policy[]): Violation[] {
    const violations: Violation[] = [];

    // Check expiration
    const expiryCheck = this.monitor.checkCertificateExpiry(cert);
    if (expiryCheck.isExpiring) {
      const policy = policies.find(p => p.framework === 'SOC2');
      
      violations.push({
        id: uuidv4(),
        policyId: policy?.id || 'system',
        policyName: policy?.name || 'Certificate Policy',
        assetId: cert.domain,
        assetType: 'certificate',
        assetIdentifier: cert.domain,
        severity: expiryCheck.severity,
        status: 'open',
        title: `Certificate Expiring in ${expiryCheck.daysLeft} Days`,
        description: `SSL/TLS certificate for ${cert.domain} will expire in ${expiryCheck.daysLeft} days. Immediate renewal is required.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'certificate',
          description: 'Certificate expiration info',
          data: JSON.stringify(cert),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Renew SSL/TLS certificate'
        }]
      });
    }

    // Check for invalid certificates
    if (!cert.isValid) {
      violations.push({
        id: uuidv4(),
        policyId: 'system',
        policyName: 'Certificate Policy',
        assetId: cert.domain,
        assetType: 'certificate',
        assetIdentifier: cert.domain,
        severity: 'critical',
        status: 'open',
        title: 'Invalid SSL/TLS Certificate',
        description: `SSL/TLS certificate for ${cert.domain} is invalid. This may cause security warnings and service disruptions.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'certificate',
          description: 'Certificate validation failure',
          data: JSON.stringify(cert),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Replace with valid certificate'
        }]
      });
    }

    return violations;
  }

  /**
   * Check domain for violations
   */
  private checkDomain(domain: DomainRecord, policies: Policy[]): Violation[] {
    const violations: Violation[] = [];
    const policy = policies.find(p => p.framework === 'SOC2');

    // Check security records
    const securityCheck = this.monitor.checkDomainSecurity(domain.domain);

    if (!securityCheck.hasSPF) {
      violations.push({
        id: uuidv4(),
        policyId: policy?.id || 'system',
        policyName: policy?.name || 'Email Security Policy',
        assetId: domain.domain,
        assetType: 'domain',
        assetIdentifier: domain.domain,
        severity: 'high',
        status: 'open',
        title: 'Missing SPF Record',
        description: `Domain ${domain.domain} is missing SPF record. This increases the risk of email spoofing and phishing attacks.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'config',
          description: 'DNS TXT records',
          data: JSON.stringify(domain.dnsRecords.filter(r => r.type === 'TXT')),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Add SPF record to domain DNS'
        }]
      });
    }

    if (!securityCheck.hasDMARC) {
      violations.push({
        id: uuidv4(),
        policyId: policy?.id || 'system',
        policyName: policy?.name || 'Email Security Policy',
        assetId: domain.domain,
        assetType: 'domain',
        assetIdentifier: domain.domain,
        severity: 'high',
        status: 'open',
        title: 'Missing DMARC Record',
        description: `Domain ${domain.domain} is missing DMARC record. This increases the risk of email spoofing and phishing attacks.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'config',
          description: 'DNS TXT records',
          data: JSON.stringify(domain.dnsRecords.filter(r => r.type === 'TXT')),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Add DMARC record to domain DNS'
        }]
      });
    }

    return violations;
  }

  /**
   * Check IP for violations
   */
  private checkIP(ipRecord: IPRecord, policies: Policy[]): Violation[] {
    const violations: Violation[] = [];
    const policy = policies.find(p => p.framework === 'CUSTOM');

    if (ipRecord.reputation === 'malicious') {
      violations.push({
        id: uuidv4(),
        policyId: policy?.id || 'system',
        policyName: policy?.name || 'IP Reputation Policy',
        assetId: ipRecord.ip,
        assetType: 'ip',
        assetIdentifier: ipRecord.ip,
        severity: 'critical',
        status: 'open',
        title: 'Malicious IP Address Detected',
        description: `IP address ${ipRecord.ip} has a malicious reputation. Immediate investigation required.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'api_response',
          description: 'IP reputation data',
          data: JSON.stringify(ipRecord),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Block IP at firewall level'
        }]
      });
    }

    if (ipRecord.isTor) {
      violations.push({
        id: uuidv4(),
        policyId: policy?.id || 'system',
        policyName: policy?.name || 'Network Security Policy',
        assetId: ipRecord.ip,
        assetType: 'ip',
        assetIdentifier: ipRecord.ip,
        severity: 'high',
        status: 'open',
        title: 'Tor Exit Node Detected',
        description: `IP address ${ipRecord.ip} is a known Tor exit node. This may indicate attempts to hide the source of network traffic.`,
        detectedAt: new Date(),
        updatedAt: new Date(),
        evidence: [{
          type: 'api_response',
          description: 'IP classification data',
          data: JSON.stringify(ipRecord),
          timestamp: new Date()
        }],
        remediation: [{
          id: uuidv4(),
          type: 'manual',
          status: 'pending',
          description: 'Review and potentially block Tor traffic'
        }]
      });
    }

    return violations;
  }

  /**
   * Create a violation manually
   */
  createViolation(data: {
    policyId: string;
    policyName: string;
    assetId: string;
    assetType: 'domain' | 'ip' | 'certificate' | 'cloud_resource';
    assetIdentifier: string;
    severity: SeverityLevel;
    title: string;
    description: string;
    evidence?: ViolationEvidence[];
  }): Violation {
    const violation: Violation = {
      id: uuidv4(),
      policyId: data.policyId,
      policyName: data.policyName,
      assetId: data.assetId,
      assetType: data.assetType,
      assetIdentifier: data.assetIdentifier,
      severity: data.severity,
      status: 'open',
      title: data.title,
      description: data.description,
      detectedAt: new Date(),
      updatedAt: new Date(),
      evidence: data.evidence || [],
      remediation: [{
        id: uuidv4(),
        type: 'manual',
        status: 'pending',
        description: 'Review and remediate violation'
      }]
    };

    this.violations.set(violation.id, violation);
    return violation;
  }

  /**
   * Update violation status
   */
  updateViolationStatus(id: string, status: ViolationStatus): Violation | undefined {
    const violation = this.violations.get(id);
    if (violation) {
      violation.status = status;
      violation.updatedAt = new Date();
      
      if (status === 'resolved') {
        violation.resolvedAt = new Date();
      }
      
      return violation;
    }
    return undefined;
  }

  /**
   * Add remediation action to a violation
   */
  addRemediation(violationId: string, remediation: Omit<RemediationAction, 'id'>): RemediationAction | undefined {
    const violation = this.violations.get(violationId);
    if (violation) {
      const newRemediation: RemediationAction = {
        ...remediation,
        id: uuidv4()
      };
      violation.remediation.push(newRemediation);
      violation.updatedAt = new Date();
      return newRemediation;
    }
    return undefined;
  }

  /**
   * Get violation by ID
   */
  getViolation(id: string): Violation | undefined {
    return this.violations.get(id);
  }

  /**
   * Get all violations
   */
  getAllViolations(): Violation[] {
    return Array.from(this.violations.values());
  }

  /**
   * Get violations by status
   */
  getViolationsByStatus(status: ViolationStatus): Violation[] {
    return this.getAllViolations().filter(v => v.status === status);
  }

  /**
   * Get violations by severity
   */
  getViolationsBySeverity(severity: SeverityLevel): Violation[] {
    return this.getAllViolations().filter(v => v.severity === severity);
  }

  /**
   * Get open violations
   */
  getOpenViolations(): Violation[] {
    return this.getAllViolations().filter(v => v.status === 'open' || v.status === 'investigating' || v.status === 'remediating');
  }

  /**
   * Get violation statistics
   */
  getStats(): {
    total: number;
    byStatus: Record<ViolationStatus, number>;
    bySeverity: Record<SeverityLevel, number>;
    openCount: number;
    resolvedCount: number;
  } {
    const violations = this.getAllViolations();
    const byStatus: Record<ViolationStatus, number> = {
      open: 0,
      investigating: 0,
      remediating: 0,
      resolved: 0,
      false_positive: 0
    };
    const bySeverity: Record<SeverityLevel, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0
    };

    for (const v of violations) {
      byStatus[v.status]++;
      bySeverity[v.severity]++;
    }

    return {
      total: violations.length,
      byStatus,
      bySeverity,
      openCount: byStatus.open + byStatus.investigating + byStatus.remediating,
      resolvedCount: byStatus.resolved
    };
  }

  /**
   * Get enabled detection rules
   */
  getRules(): DetectionRule[] {
    return this.rules.filter(r => r.enabled);
  }

  /**
   * Add a custom detection rule
   */
  addRule(rule: DetectionRule): void {
    this.rules.push(rule);
  }

  /**
   * Enable/disable a rule
   */
  toggleRule(ruleId: string, enabled: boolean): void {
    const rule = this.rules.find(r => r.id === ruleId);
    if (rule) {
      rule.enabled = enabled;
    }
  }

  /**
   * Delete a violation
   */
  deleteViolation(id: string): boolean {
    return this.violations.delete(id);
  }
}

export default ViolationDetector;
