// Core module exports
export { PolicyParser } from './policy-parser.js';
export { InfrastructureMonitor } from './infrastructure-monitor.js';
export { AgentMemory } from './agent-memory.js';
export { ViolationDetector } from './violation-detector.js';
export { SOARAutomation } from './soar-automation.js';
export { ReportGenerator } from './report-generator.js';
// Main ComplianceAgent class that ties everything together
import { PolicyParser } from './policy-parser.js';
import { InfrastructureMonitor } from './infrastructure-monitor.js';
import { AgentMemory } from './agent-memory.js';
import { ViolationDetector } from './violation-detector.js';
import { SOARAutomation } from './soar-automation.js';
import { ReportGenerator } from './report-generator.js';
export class ComplianceAgent {
    policyParser;
    monitor;
    memory;
    detector;
    soar;
    reportGenerator;
    organizationId;
    organizationName;
    constructor(organizationId, organizationName) {
        this.organizationId = organizationId;
        this.organizationName = organizationName;
        this.policyParser = new PolicyParser();
        this.monitor = new InfrastructureMonitor();
        this.memory = new AgentMemory();
        this.detector = new ViolationDetector(this.monitor);
        this.soar = new SOARAutomation();
        this.reportGenerator = new ReportGenerator();
    }
    // ============================================================================
    // Policy Management
    // ============================================================================
    async loadPolicy(filePath) {
        const policy = await this.policyParser.parsePolicyFile(filePath);
        this.memory.storePolicy(policy);
        return policy;
    }
    getPolicies() {
        return this.policyParser.getAllPolicies();
    }
    getActivePolicies() {
        return this.policyParser.getActivePolicies();
    }
    getPoliciesByFramework(framework) {
        return this.policyParser.getPoliciesByFramework(framework);
    }
    createSamplePolicies() {
        const soc2 = this.policyParser.createSampleSOC2Policy();
        const iso27001 = this.policyParser.createSampleISO27001Policy();
        this.memory.storePolicy(soc2);
        this.memory.storePolicy(iso27001);
    }
    // ============================================================================
    // Infrastructure Monitoring
    // ============================================================================
    async addDomain(domain) {
        return this.monitor.addDomain(domain, this.organizationId);
    }
    async addIP(ip) {
        return this.monitor.addIP(ip, this.organizationId);
    }
    async addCertificate(domain) {
        return this.monitor.addCertificate(domain, this.organizationId);
    }
    async refreshInfrastructure() {
        await this.monitor.refreshAll();
    }
    getMonitoredAssets() {
        return this.monitor.getAssets();
    }
    // ============================================================================
    // Violation Detection
    // ============================================================================
    async runDetection() {
        const policies = this.getActivePolicies();
        const violations = await this.detector.runDetection(policies);
        // Store violations in memory
        for (const violation of violations) {
            this.memory.storeViolation(violation);
            // Execute SOAR playbooks
            await this.soar.executePlaybooks(violation);
        }
        return violations;
    }
    getViolations() {
        return this.detector.getAllViolations();
    }
    getOpenViolations() {
        return this.detector.getOpenViolations();
    }
    getViolationStats() {
        return this.detector.getStats();
    }
    // ============================================================================
    // SOAR Automation
    // ============================================================================
    getIncidents() {
        return this.soar.getAllIncidents();
    }
    getPlaybooks() {
        return this.soar.getAllPlaybooks();
    }
    getSOARStats() {
        return this.soar.getStats();
    }
    // ============================================================================
    // Reports
    // ============================================================================
    generateReport(options) {
        return this.reportGenerator.generateReport({
            ...options,
            policies: this.getPolicies(),
            violations: this.getViolations(),
            incidents: this.getIncidents(),
            generatedBy: 'ComplianceAgent'
        });
    }
    // ============================================================================
    // Agent Memory
    // ============================================================================
    searchMemory(query, type) {
        return this.memory.search(query, 10, type);
    }
    getMemoryStats() {
        return this.memory.getStats();
    }
    // ============================================================================
    // Full Compliance Scan
    // ============================================================================
    async runFullScan() {
        console.log('🔍 Running full compliance scan...');
        // Step 1: Refresh infrastructure
        console.log('  📡 Refreshing infrastructure...');
        await this.refreshInfrastructure();
        // Step 2: Run violation detection
        console.log('  ⚠️  Detecting violations...');
        const violations = await this.runDetection();
        // Get results
        const policies = this.getPolicies();
        const assets = this.getMonitoredAssets();
        const incidents = this.getIncidents();
        console.log(`\n✅ Scan complete!`);
        console.log(`   Policies: ${policies.length}`);
        console.log(`   Assets: ${assets.length}`);
        console.log(`   Violations: ${violations.length}`);
        console.log(`   Incidents: ${incidents.length}`);
        return {
            policies,
            assets,
            violations,
            incidents
        };
    }
}
export default ComplianceAgent;
//# sourceMappingURL=index.js.map