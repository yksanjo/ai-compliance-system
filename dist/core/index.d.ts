export { PolicyParser } from './policy-parser.js';
export { InfrastructureMonitor } from './infrastructure-monitor.js';
export { AgentMemory } from './agent-memory.js';
export { ViolationDetector } from './violation-detector.js';
export { SOARAutomation } from './soar-automation.js';
export { ReportGenerator } from './report-generator.js';
import { Policy, Violation, ComplianceFramework, MonitoredAsset } from '../types/index.js';
export declare class ComplianceAgent {
    private policyParser;
    private monitor;
    private memory;
    private detector;
    private soar;
    private reportGenerator;
    private organizationId;
    private organizationName;
    constructor(organizationId: string, organizationName: string);
    loadPolicy(filePath: string): Promise<Policy>;
    getPolicies(): Policy[];
    getActivePolicies(): Policy[];
    getPoliciesByFramework(framework: ComplianceFramework): Policy[];
    createSamplePolicies(): void;
    addDomain(domain: string): Promise<MonitoredAsset>;
    addIP(ip: string): Promise<MonitoredAsset>;
    addCertificate(domain: string): Promise<MonitoredAsset>;
    refreshInfrastructure(): Promise<void>;
    getMonitoredAssets(): MonitoredAsset[];
    runDetection(): Promise<Violation[]>;
    getViolations(): Violation[];
    getOpenViolations(): Violation[];
    getViolationStats(): {
        total: number;
        byStatus: Record<import("../types/index.js").ViolationStatus, number>;
        bySeverity: Record<import("../types/index.js").SeverityLevel, number>;
        openCount: number;
        resolvedCount: number;
    };
    getIncidents(): import("../types/index.js").Incident[];
    getPlaybooks(): import("../types/index.js").Playbook[];
    getSOARStats(): {
        totalPlaybooks: number;
        enabledPlaybooks: number;
        totalIncidents: number;
        openIncidents: number;
        closedIncidents: number;
        recentExecutions: number;
    };
    generateReport(options: {
        framework: ComplianceFramework;
        type: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
        period: {
            start: Date;
            end: Date;
        };
    }): import("../types/index.js").ComplianceReport;
    searchMemory(query: string, type?: 'policy' | 'violation' | 'incident' | 'knowledge'): import("../types/index.js").MemoryEntry[];
    getMemoryStats(): {
        totalMemories: number;
        byType: Record<string, number>;
        averageAccessCount: number;
        conversationEntries: number;
    };
    runFullScan(): Promise<{
        policies: Policy[];
        assets: MonitoredAsset[];
        violations: Violation[];
        incidents: ReturnType<typeof this.soar.getAllIncidents>;
    }>;
}
export default ComplianceAgent;
//# sourceMappingURL=index.d.ts.map