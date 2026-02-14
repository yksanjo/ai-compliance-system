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
import { Policy, Violation, ComplianceFramework, MonitoredAsset } from '../types/index.js';

export class ComplianceAgent {
  private policyParser: PolicyParser;
  private monitor: InfrastructureMonitor;
  private memory: AgentMemory;
  private detector: ViolationDetector;
  private soar: SOARAutomation;
  private reportGenerator: ReportGenerator;
  private organizationId: string;
  private organizationName: string;

  constructor(organizationId: string, organizationName: string) {
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

  async loadPolicy(filePath: string): Promise<Policy> {
    const policy = await this.policyParser.parsePolicyFile(filePath);
    this.memory.storePolicy(policy);
    return policy;
  }

  getPolicies(): Policy[] {
    return this.policyParser.getAllPolicies();
  }

  getActivePolicies(): Policy[] {
    return this.policyParser.getActivePolicies();
  }

  getPoliciesByFramework(framework: ComplianceFramework): Policy[] {
    return this.policyParser.getPoliciesByFramework(framework);
  }

  createSamplePolicies(): void {
    const soc2 = this.policyParser.createSampleSOC2Policy();
    const iso27001 = this.policyParser.createSampleISO27001Policy();
    
    this.memory.storePolicy(soc2);
    this.memory.storePolicy(iso27001);
  }

  // ============================================================================
  // Infrastructure Monitoring
  // ============================================================================

  async addDomain(domain: string): Promise<MonitoredAsset> {
    return this.monitor.addDomain(domain, this.organizationId);
  }

  async addIP(ip: string): Promise<MonitoredAsset> {
    return this.monitor.addIP(ip, this.organizationId);
  }

  async addCertificate(domain: string): Promise<MonitoredAsset> {
    return this.monitor.addCertificate(domain, this.organizationId);
  }

  async refreshInfrastructure(): Promise<void> {
    await this.monitor.refreshAll();
  }

  getMonitoredAssets(): MonitoredAsset[] {
    return this.monitor.getAssets();
  }

  // ============================================================================
  // Violation Detection
  // ============================================================================

  async runDetection(): Promise<Violation[]> {
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

  getViolations(): Violation[] {
    return this.detector.getAllViolations();
  }

  getOpenViolations(): Violation[] {
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

  generateReport(options: {
    framework: ComplianceFramework;
    type: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
    period: { start: Date; end: Date };
  }) {
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

  searchMemory(query: string, type?: 'policy' | 'violation' | 'incident' | 'knowledge') {
    return this.memory.search(query, 10, type);
  }

  getMemoryStats() {
    return this.memory.getStats();
  }

  // ============================================================================
  // Full Compliance Scan
  // ============================================================================

  async runFullScan(): Promise<{
    policies: Policy[];
    assets: MonitoredAsset[];
    violations: Violation[];
    incidents: ReturnType<typeof this.soar.getAllIncidents>;
  }> {
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
