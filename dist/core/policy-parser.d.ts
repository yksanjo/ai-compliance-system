import { Policy, ComplianceFramework } from '../types/index.js';
export declare class PolicyParser {
    private policies;
    /**
     * Parse a policy document from file
     */
    parsePolicyFile(filePath: string): Promise<Policy>;
    /**
     * Parse policy from markdown content
     */
    parseMarkdown(content: string, source: string): Policy;
    /**
     * Parse policy from JSON content
     */
    parseJSON(content: string, source: string): Policy;
    /**
     * Parse policy from YAML content
     */
    parseYAML(content: string, source: string): Policy;
    /**
     * Create a sample SOC2 policy
     */
    createSampleSOC2Policy(): Policy;
    /**
     * Create a sample ISO 27001 policy
     */
    createSampleISO27001Policy(): Policy;
    private parseRequirements;
    private parseControls;
    private normalizeFramework;
    private normalizeStatus;
    private normalizeSeverity;
    getPolicy(id: string): Policy | undefined;
    getAllPolicies(): Policy[];
    getPoliciesByFramework(framework: ComplianceFramework): Policy[];
    getActivePolicies(): Policy[];
    deletePolicy(id: string): boolean;
}
export default PolicyParser;
//# sourceMappingURL=policy-parser.d.ts.map