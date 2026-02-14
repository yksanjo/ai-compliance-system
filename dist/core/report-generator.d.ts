import { ComplianceReport, Policy, Violation, Incident, ComplianceFramework } from '../types/index.js';
export declare class ReportGenerator {
    /**
     * Generate a compliance report
     */
    generateReport(options: {
        framework: ComplianceFramework;
        type: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
        policies: Policy[];
        violations: Violation[];
        incidents: Incident[];
        period: {
            start: Date;
            end: Date;
        };
        generatedBy: string;
    }): ComplianceReport;
    /**
     * Generate SOC2 report
     */
    generateSOC2Report(options: {
        policies: Policy[];
        violations: Violation[];
        incidents: Incident[];
        period: {
            start: Date;
            end: Date;
        };
        generatedBy: string;
        type?: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
    }): ComplianceReport;
    /**
     * Generate ISO 27001 report
     */
    generateISO27001Report(options: {
        policies: Policy[];
        violations: Violation[];
        incidents: Incident[];
        period: {
            start: Date;
            end: Date;
        };
        generatedBy: string;
        type?: 'executive' | 'detailed' | 'gap_analysis' | 'audit';
    }): ComplianceReport;
    /**
     * Generate report summary
     */
    private generateSummary;
    /**
     * Generate findings from violations
     */
    private generateFindings;
    /**
     * Get remediation recommendation based on violation
     */
    private getRecommendation;
    /**
     * Generate control status
     */
    private generateControlStatus;
    /**
     * Generate evidence items
     */
    private generateEvidence;
    /**
     * Map violation evidence type to report evidence type
     */
    private mapEvidenceType;
    /**
     * Export report to markdown format
     */
    exportToMarkdown(report: ComplianceReport): string;
    /**
     * Export report to JSON format
     */
    exportToJSON(report: ComplianceReport): string;
    /**
     * Export report to HTML format
     */
    exportToHTML(report: ComplianceReport): string;
    private getSeverityEmoji;
    private getSeverityColor;
    private getStatusEmoji;
}
export default ReportGenerator;
//# sourceMappingURL=report-generator.d.ts.map