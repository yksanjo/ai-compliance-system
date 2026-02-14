import { v4 as uuidv4 } from 'uuid';
import {
  ComplianceReport,
  ReportSummary,
  ReportFinding,
  ControlStatus,
  EvidenceItem,
  Policy,
  Violation,
  Incident,
  ComplianceFramework,
  Control
} from '../types/index.js';

export class ReportGenerator {
  /**
   * Generate a compliance report
   */
  generateReport(options: {
    framework: ComplianceFramework;
    type: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
    policies: Policy[];
    violations: Violation[];
    incidents: Incident[];
    period: { start: Date; end: Date };
    generatedBy: string;
  }): ComplianceReport {
    const { framework, type, policies, violations, incidents, period, generatedBy } = options;

    const frameworkPolicies = policies.filter(p => p.framework === framework || framework === 'CUSTOM');
    const frameworkViolations = violations.filter(v => 
      frameworkPolicies.some(p => p.id === v.policyId)
    );

    const summary = this.generateSummary(frameworkPolicies, frameworkViolations);
    const findings = this.generateFindings(frameworkViolations);
    const controls = this.generateControlStatus(frameworkPolicies, frameworkViolations);
    const evidence = this.generateEvidence(frameworkViolations, frameworkPolicies);

    const report: ComplianceReport = {
      id: uuidv4(),
      framework,
      type,
      period,
      summary,
      findings,
      controls,
      evidence,
      generatedAt: new Date(),
      generatedBy
    };

    return report;
  }

  /**
   * Generate SOC2 report
   */
  generateSOC2Report(options: {
    policies: Policy[];
    violations: Violation[];
    incidents: Incident[];
    period: { start: Date; end: Date };
    generatedBy: string;
    type?: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
  }): ComplianceReport {
    return this.generateReport({
      framework: 'SOC2',
      type: options.type || 'detailed',
      policies: options.policies,
      violations: options.violations,
      incidents: options.incidents,
      period: options.period,
      generatedBy: options.generatedBy
    });
  }

  /**
   * Generate ISO 27001 report
   */
  generateISO27001Report(options: {
    policies: Policy[];
    violations: Violation[];
    incidents: Incident[];
    period: { start: Date; end: Date };
    generatedBy: string;
    type?: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
  }): ComplianceReport {
    return this.generateReport({
      framework: 'ISO27001',
      type: options.type || 'detailed',
      policies: options.policies,
      violations: options.violations,
      incidents: options.incidents,
      period: options.period,
      generatedBy: options.generatedBy
    });
  }

  /**
   * Generate report summary
   */
  private generateSummary(policies: Policy[], violations: Violation[]): ReportSummary {
    // Get all controls from policies
    const allControls: Control[] = [];
    for (const policy of policies) {
      allControls.push(...policy.controls);
    }

    const totalControls = allControls.length;
    const compliantControls = allControls.filter(c => c.testResult === 'pass').length;
    const nonCompliantControls = violations.filter(v => 
      v.status !== 'resolved' && v.status !== 'false_positive'
    ).length;
    const notApplicableControls = 0; // Would need more sophisticated logic

    const compliancePercentage = totalControls > 0 
      ? Math.round((compliantControls / totalControls) * 100) 
      : 100;

    const criticalFindings = violations.filter(v => v.severity === 'critical' && v.status !== 'resolved').length;
    const highFindings = violations.filter(v => v.severity === 'high' && v.status !== 'resolved').length;
    const mediumFindings = violations.filter(v => v.severity === 'medium' && v.status !== 'resolved').length;

    // Calculate risk score (0-100, higher is worse)
    const riskScore = Math.min(100, 
      (criticalFindings * 10) + (highFindings * 5) + (mediumFindings * 2)
    );

    // Determine trend
    let trend: 'improving' | 'stable' | 'degrading' = 'stable';
    const resolvedCount = violations.filter(v => v.status === 'resolved').length;
    const openCount = violations.filter(v => v.status === 'open').length;
    
    if (resolvedCount > openCount) {
      trend = 'improving';
    } else if (openCount > resolvedCount * 2) {
      trend = 'degrading';
    }

    return {
      totalControls,
      compliantControls,
      nonCompliantControls,
      notApplicableControls,
      compliancePercentage,
      criticalFindings,
      highFindings,
      mediumFindings,
      riskScore,
      trend
    };
  }

  /**
   * Generate findings from violations
   */
  private generateFindings(violations: Violation[]): ReportFinding[] {
    const findings: ReportFinding[] = [];

    for (const violation of violations) {
      if (violation.status === 'resolved' || violation.status === 'false_positive') {
        continue;
      }

      findings.push({
        id: violation.id,
        title: violation.title,
        description: violation.description,
        severity: violation.severity,
        controlId: violation.controlId || '',
        recommendation: this.getRecommendation(violation),
        evidence: violation.evidence.map(e => e.description)
      });
    }

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return findings;
  }

  /**
   * Get remediation recommendation based on violation
   */
  private getRecommendation(violation: Violation): string {
    const recommendations: Record<string, string> = {
      'Certificate Expiring': 'Renew SSL/TLS certificate immediately. Set up automated renewal.',
      'Missing SPF Record': 'Add SPF record to domain DNS. Use v=spf1 include:_spf.example.com ~all',
      'Missing DMARC Record': 'Add DMARC record to domain DNS. Start with p=none policy.',
      'Malicious IP': 'Block IP at firewall/WAF level. Investigate source of traffic.',
      'Tor Exit Node': 'Review access logs. Consider blocking Tor exit nodes.',
      'Invalid Certificate': 'Replace with valid certificate from trusted CA.'
    };

    for (const [key, rec] of Object.entries(recommendations)) {
      if (violation.title.includes(key) || violation.description.includes(key)) {
        return rec;
      }
    }

    return 'Review violation details and implement appropriate remediation.';
  }

  /**
   * Generate control status
   */
  private generateControlStatus(policies: Policy[], violations: Violation[]): ControlStatus[] {
    const controls: ControlStatus[] = [];

    for (const policy of policies) {
      for (const control of policy.controls) {
        const controlViolations = violations.filter(v => 
          v.controlId === control.id && v.status !== 'resolved'
        );

        let status: ControlStatus['status'] = 'not_tested';
        
        if (control.tested && control.testResult) {
          status = control.testResult === 'pass' ? 'compliant' : 'non_compliant';
        } else if (controlViolations.length > 0) {
          status = 'non_compliant';
        }

        controls.push({
          controlId: control.id,
          name: control.name,
          status,
          lastTested: control.lastTested,
          testResult: control.testResult,
          findings: controlViolations.map(v => v.title)
        });
      }
    }

    return controls;
  }

  /**
   * Generate evidence items
   */
  private generateEvidence(violations: Violation[], policies: Policy[]): EvidenceItem[] {
    const evidence: EvidenceItem[] = [];

    // Add violation evidence
    for (const violation of violations) {
      for (const ev of violation.evidence) {
        evidence.push({
          id: uuidv4(),
          controlId: violation.controlId || '',
          type: this.mapEvidenceType(ev.type),
          description: ev.description,
          collectedAt: ev.timestamp,
          data: ev.data
        });
      }
    }

    // Add policy evidence
    for (const policy of policies) {
      evidence.push({
        id: uuidv4(),
        controlId: '',
        type: 'document',
        description: `Policy: ${policy.name}`,
        collectedAt: policy.parsedAt,
        data: policy.content.substring(0, 1000) // First 1000 chars
      });
    }

    return evidence;
  }

  /**
   * Map violation evidence type to report evidence type
   */
  private mapEvidenceType(type: string): EvidenceItem['type'] {
    switch (type) {
      case 'screenshot':
        return 'screenshot';
      case 'log':
        return 'log';
      case 'config':
        return 'config';
      case 'certificate':
        return 'certificate';
      default:
        return 'document';
    }
  }

  /**
   * Export report to markdown format
   */
  exportToMarkdown(report: ComplianceReport): string {
    let md = `# ${report.framework} Compliance Report\n\n`;
    md += `**Report ID:** ${report.id}\n`;
    md += `**Type:** ${report.type}\n`;
    md += `**Period:** ${report.period.start.toISOString().split('T')[0]} - ${report.period.end.toISOString().split('T')[0]}\n`;
    md += `**Generated:** ${report.generatedAt.toISOString()}\n`;
    md += `**Generated By:** ${report.generatedBy}\n\n`;

    // Summary
    md += `## Executive Summary\n\n`;
    md += `| Metric | Value |\n`;
    md += `|--------|-------|\n`;
    md += `| Compliance Score | ${report.summary.compliancePercentage}% |\n`;
    md += `| Total Controls | ${report.summary.totalControls} |\n`;
    md += `| Compliant Controls | ${report.summary.compliantControls} |\n`;
    md += `| Non-Compliant Controls | ${report.summary.nonCompliantControls} |\n`;
    md += `| Critical Findings | ${report.summary.criticalFindings} |\n`;
    md += `| High Findings | ${report.summary.highFindings} |\n`;
    md += `| Medium Findings | ${report.summary.mediumFindings} |\n`;
    md += `| Risk Score | ${report.summary.riskScore}/100 |\n`;
    md += `| Trend | ${report.summary.trend} |\n\n`;

    // Findings
    if (report.findings.length > 0) {
      md += `## Findings\n\n`;
      for (const finding of report.findings) {
        md += `### ${this.getSeverityEmoji(finding.severity)} ${finding.title}\n\n`;
        md += `**Severity:** ${finding.severity.toUpperCase()}\n\n`;
        md += `**Description:** ${finding.description}\n\n`;
        md += `**Recommendation:** ${finding.recommendation}\n\n`;
        if (finding.evidence.length > 0) {
          md += `**Evidence:**\n`;
          for (const ev of finding.evidence) {
            md += `- ${ev}\n`;
          }
          md += `\n`;
        }
      }
    }

    // Controls
    if (report.controls.length > 0) {
      md += `## Control Status\n\n`;
      md += `| Control ID | Name | Status | Last Tested |\n`;
      md += `|------------|------|--------|-------------|\n`;
      for (const control of report.controls) {
        const status = this.getStatusEmoji(control.status);
        const lastTested = control.lastTested 
          ? control.lastTested.toISOString().split('T')[0] 
          : 'N/A';
        md += `| ${control.controlId} | ${control.name} | ${status} ${control.status} | ${lastTested} |\n`;
      }
      md += `\n`;
    }

    return md;
  }

  /**
   * Export report to JSON format
   */
  exportToJSON(report: ComplianceReport): string {
    return JSON.stringify(report, null, 2);
  }

  /**
   * Export report to HTML format
   */
  exportToHTML(report: ComplianceReport): string {
    const html = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${report.framework} Compliance Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #1a365d; border-bottom: 2px solid #1a365d; padding-bottom: 10px; }
        h2 { color: #2c5282; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        th { background-color: #f7fafc; font-weight: 600; }
        .critical { color: #c53030; font-weight: bold; }
        .high { color: #dd6b20; font-weight: bold; }
        .medium { color: #d69e2e; }
        .low { color: #38a169; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; }
        .badge-critical { background-color: #fed7d7; color: #c53030; }
        .badge-high { background-color: #feebc8; color: #dd6b20; }
        .badge-compliant { background-color: #c6f6d5; color: #38a169; }
        .badge-non-compliant { background-color: #fed7d7; color: #c53030; }
    </style>
</head>
<body>
    <h1>${report.framework} Compliance Report</h1>
    
    <p><strong>Report ID:</strong> ${report.id}</p>
    <p><strong>Type:</strong> ${report.type}</p>
    <p><strong>Period:</strong> ${report.period.start.toISOString().split('T')[0]} - ${report.period.end.toISOString().split('T')[0]}</p>
    <p><strong>Generated:</strong> ${report.generatedAt.toISOString()}</p>
    
    <h2>Executive Summary</h2>
    <table>
        <tr><th>Metric</th><th>Value</th></tr>
        <tr><td>Compliance Score</td><td><strong>${report.summary.compliancePercentage}%</strong></td></tr>
        <tr><td>Total Controls</td><td>${report.summary.totalControls}</td></tr>
        <tr><td>Compliant Controls</td><td>${report.summary.compliantControls}</td></tr>
        <tr><td>Non-Compliant Controls</td><td>${report.summary.nonCompliantControls}</td></tr>
        <tr><td>Critical Findings</td><td class="critical">${report.summary.criticalFindings}</td></tr>
        <tr><td>High Findings</td><td class="high">${report.summary.highFindings}</td></tr>
        <tr><td>Medium Findings</td><td class="medium">${report.summary.mediumFindings}</td></tr>
        <tr><td>Risk Score</td><td>${report.summary.riskScore}/100</td></tr>
        <tr><td>Trend</td><td>${report.summary.trend}</td></tr>
    </table>
    
    ${report.findings.length > 0 ? `
    <h2>Findings</h2>
    ${report.findings.map(f => `
    <div style="margin: 20px 0; padding: 15px; border-left: 4px solid ${this.getSeverityColor(f.severity)}; background: #f7fafc;">
        <h3>${this.getSeverityEmoji(f.severity)} ${f.title}</h3>
        <p><strong>Severity:</strong> <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span></p>
        <p>${f.description}</p>
        <p><strong>Recommendation:</strong> ${f.recommendation}</p>
    </div>
    `).join('')}
    ` : ''}
    
    ${report.controls.length > 0 ? `
    <h2>Control Status</h2>
    <table>
        <tr><th>Control ID</th><th>Name</th><th>Status</th><th>Last Tested</th></tr>
        ${report.controls.map(c => `
        <tr>
            <td>${c.controlId}</td>
            <td>${c.name}</td>
            <td><span class="badge badge-${c.status === 'compliant' ? 'compliant' : 'non-compliant'}">${c.status}</span></td>
            <td>${c.lastTested ? c.lastTested.toISOString().split('T')[0] : 'N/A'}</td>
        </tr>
        `).join('')}
    </table>
    ` : ''}
</body>
</html>`;

    return html;
  }

  private getSeverityEmoji(severity: string): string {
    switch (severity) {
      case 'critical': return '🔴';
      case 'high': return '🟠';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  }

  private getSeverityColor(severity: string): string {
    switch (severity) {
      case 'critical': return '#c53030';
      case 'high': return '#dd6b20';
      case 'medium': return '#d69e2e';
      case 'low': return '#38a169';
      default: return '#718096';
    }
  }

  private getStatusEmoji(status: string): string {
    switch (status) {
      case 'compliant': return '✅';
      case 'non_compliant': return '❌';
      case 'not_applicable': return '➖';
      default: return '⚪';
    }
  }
}

export default ReportGenerator;
