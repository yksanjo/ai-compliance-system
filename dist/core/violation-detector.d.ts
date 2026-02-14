import { Violation, ViolationEvidence, RemediationAction, DetectionRule, Policy, SeverityLevel, ViolationStatus } from '../types/index.js';
import { InfrastructureMonitor } from './infrastructure-monitor.js';
export declare class ViolationDetector {
    private violations;
    private rules;
    private monitor;
    constructor(monitor: InfrastructureMonitor);
    /**
     * Initialize default detection rules
     */
    private initializeDefaultRules;
    /**
     * Check all monitored assets against detection rules
     */
    runDetection(policies: Policy[]): Promise<Violation[]>;
    /**
     * Check a specific asset for violations
     */
    checkAsset(identifier: string, type: 'domain' | 'ip' | 'certificate' | 'cloud_resource', policies: Policy[]): Promise<Violation[]>;
    /**
     * Check certificate for violations
     */
    private checkCertificate;
    /**
     * Check domain for violations
     */
    private checkDomain;
    /**
     * Check IP for violations
     */
    private checkIP;
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
    }): Violation;
    /**
     * Update violation status
     */
    updateViolationStatus(id: string, status: ViolationStatus): Violation | undefined;
    /**
     * Add remediation action to a violation
     */
    addRemediation(violationId: string, remediation: Omit<RemediationAction, 'id'>): RemediationAction | undefined;
    /**
     * Get violation by ID
     */
    getViolation(id: string): Violation | undefined;
    /**
     * Get all violations
     */
    getAllViolations(): Violation[];
    /**
     * Get violations by status
     */
    getViolationsByStatus(status: ViolationStatus): Violation[];
    /**
     * Get violations by severity
     */
    getViolationsBySeverity(severity: SeverityLevel): Violation[];
    /**
     * Get open violations
     */
    getOpenViolations(): Violation[];
    /**
     * Get violation statistics
     */
    getStats(): {
        total: number;
        byStatus: Record<ViolationStatus, number>;
        bySeverity: Record<SeverityLevel, number>;
        openCount: number;
        resolvedCount: number;
    };
    /**
     * Get enabled detection rules
     */
    getRules(): DetectionRule[];
    /**
     * Add a custom detection rule
     */
    addRule(rule: DetectionRule): void;
    /**
     * Enable/disable a rule
     */
    toggleRule(ruleId: string, enabled: boolean): void;
    /**
     * Delete a violation
     */
    deleteViolation(id: string): boolean;
}
export default ViolationDetector;
//# sourceMappingURL=violation-detector.d.ts.map