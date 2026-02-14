import { v4 as uuidv4 } from 'uuid';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'yaml';
// Simple markdown parser for policy documents
export class PolicyParser {
    policies = new Map();
    /**
     * Parse a policy document from file
     */
    async parsePolicyFile(filePath) {
        const ext = path.extname(filePath).toLowerCase();
        const content = fs.readFileSync(filePath, 'utf-8');
        switch (ext) {
            case '.md':
                return this.parseMarkdown(content, filePath);
            case '.json':
                return this.parseJSON(content, filePath);
            case '.yaml':
            case '.yml':
                return this.parseYAML(content, filePath);
            default:
                throw new Error(`Unsupported file format: ${ext}`);
        }
    }
    /**
     * Parse policy from markdown content
     */
    parseMarkdown(content, source) {
        const lines = content.split('\n');
        let name = '';
        let description = '';
        let framework = 'CUSTOM';
        let status = 'draft';
        let version = '1.0.0';
        const requirements = [];
        const controls = [];
        const tags = [];
        let owner = 'Unknown';
        let department = 'Unknown';
        let effectiveDate = new Date();
        let reviewDate = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
        let currentSection = '';
        let currentRequirement = null;
        let currentControl = null;
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i].trim();
            // Parse frontmatter-like headers
            if (line.startsWith('# ')) {
                name = line.substring(2).trim();
            }
            else if (line.startsWith('## ')) {
                currentSection = line.substring(3).trim().toLowerCase();
                // Process completed requirement/control
                if (currentRequirement && currentRequirement.id) {
                    requirements.push(currentRequirement);
                    currentRequirement = null;
                }
                if (currentControl && currentControl.id) {
                    controls.push(currentControl);
                    currentControl = null;
                }
            }
            else if (line.startsWith('### ')) {
                const subSection = line.substring(4).trim().toLowerCase();
                // Framework detection
                if (subSection.includes('framework') || subSection.includes('standard')) {
                    const frameworkMatch = content.match(/(SOC2|ISO\s?27001|HIPAA|GDPR|PCI-DSS)/i);
                    if (frameworkMatch) {
                        framework = this.normalizeFramework(frameworkMatch[1]);
                    }
                }
            }
            else if (line.startsWith('**') && line.includes(':')) {
                // Parse key-value metadata
                const match = line.match(/\*\*(\w+):\*\*\s*(.+)/);
                if (match) {
                    const key = match[1].toLowerCase();
                    const value = match[2].trim();
                    switch (key) {
                        case 'version':
                            version = value;
                            break;
                        case 'status':
                            status = this.normalizeStatus(value);
                            break;
                        case 'owner':
                            owner = value;
                            break;
                        case 'department':
                            department = value;
                            break;
                        case 'tags':
                            tags.push(...value.split(',').map(t => t.trim()));
                            break;
                    }
                }
            }
            // Parse requirements section
            if (currentSection === 'requirements' || currentSection === ('controls and requirements')) {
                // Check for numbered requirement
                const reqMatch = line.match(/^(\d+\.)\s*(.+)/);
                if (reqMatch) {
                    if (currentRequirement && currentRequirement.id) {
                        requirements.push(currentRequirement);
                    }
                    currentRequirement = {
                        id: uuidv4(),
                        description: reqMatch[2],
                        category: 'General',
                        mandatory: !line.toLowerCase().includes('optional'),
                        relatedControls: [],
                        severity: 'medium'
                    };
                }
                else if (line.startsWith('-') && currentRequirement) {
                    // Additional details for requirement
                    const detail = line.substring(1).trim();
                    if (detail.startsWith('Category:')) {
                        currentRequirement.category = detail.substring(9).trim();
                    }
                    else if (detail.startsWith('Severity:')) {
                        currentRequirement.severity = this.normalizeSeverity(detail.substring(9).trim());
                    }
                }
            }
            // Parse controls section
            if (currentSection === 'controls' || currentSection === 'control objectives') {
                const controlMatch = line.match(/^([A-Z]+\d+)\s*[-:]\s*(.+)/);
                if (controlMatch) {
                    if (currentControl && currentControl.id) {
                        controls.push(currentControl);
                    }
                    currentControl = {
                        id: controlMatch[1],
                        name: controlMatch[2],
                        description: '',
                        implementation: '',
                        tested: false
                    };
                }
                else if (line.startsWith('-') && currentControl) {
                    const detail = line.substring(1).trim();
                    if (detail.startsWith('Implementation:')) {
                        currentControl.implementation = detail.substring(15).trim();
                    }
                    else if (!currentControl.description) {
                        currentControl.description = detail;
                    }
                }
            }
            // Description extraction from first paragraph
            if (!description && i > 0 && line && !line.startsWith('#') && !line.startsWith('##')) {
                description = line;
            }
        }
        // Push any remaining items
        if (currentRequirement && currentRequirement.id) {
            requirements.push(currentRequirement);
        }
        if (currentControl && currentControl.id) {
            controls.push(currentControl);
        }
        // If no requirements were parsed, create a default one
        if (requirements.length === 0) {
            requirements.push({
                id: uuidv4(),
                description: 'All policy requirements must be followed',
                category: 'General',
                mandatory: true,
                relatedControls: controls.map(c => c.id),
                severity: 'high'
            });
        }
        const policy = {
            id: uuidv4(),
            name,
            description: description || `Policy: ${name}`,
            framework,
            status,
            version,
            requirements,
            controls,
            metadata: {
                owner,
                department,
                effectiveDate,
                reviewDate,
                tags,
                attachments: []
            },
            content,
            parsedAt: new Date()
        };
        this.policies.set(policy.id, policy);
        return policy;
    }
    /**
     * Parse policy from JSON content
     */
    parseJSON(content, source) {
        const data = JSON.parse(content);
        const policy = {
            id: data.id || uuidv4(),
            name: data.name || 'Unnamed Policy',
            description: data.description || '',
            framework: this.normalizeFramework(data.framework || 'CUSTOM'),
            status: this.normalizeStatus(data.status || 'draft'),
            version: data.version || '1.0.0',
            requirements: this.parseRequirements(data.requirements || []),
            controls: this.parseControls(data.controls || []),
            metadata: {
                owner: data.owner || 'Unknown',
                department: data.department || 'Unknown',
                effectiveDate: new Date(data.effectiveDate || Date.now()),
                reviewDate: new Date(data.reviewDate || Date.now() + 365 * 24 * 60 * 60 * 1000),
                tags: data.tags || [],
                attachments: data.attachments || []
            },
            content,
            parsedAt: new Date()
        };
        this.policies.set(policy.id, policy);
        return policy;
    }
    /**
     * Parse policy from YAML content
     */
    parseYAML(content, source) {
        const data = yaml.parse(content);
        return this.parseJSON(JSON.stringify(data), source);
    }
    /**
     * Create a sample SOC2 policy
     */
    createSampleSOC2Policy() {
        const policyContent = `# SOC 2 Security Policy

**Version:** 1.0.0
**Status:** Active
**Owner:** Security Team
**Department:** Information Security

## Overview

This policy establishes the security requirements for maintaining SOC 2 compliance. All employees and contractors must adhere to these security controls.

## Requirements

1. All external-facing systems must use TLS 1.2 or higher
2. Multi-factor authentication must be enabled for all administrative access
3. Security logs must be retained for at least 90 days
4. Vulnerability scans must be performed quarterly
5. All access must be on a need-to-know basis
6. Data encryption at rest is required for sensitive data

## Controls

CC6.1 - Logical and Physical Access Controls
- Implementation: Access is controlled through IAM with RBAC

CC7.1 - System Operations
- Implementation: Monitoring and alerting configured

CC7.2 - Change Management
- Implementation: All changes require approval

CC8.1 - Risk Assessment
- Implementation: Annual risk assessment performed
`;
        return this.parseMarkdown(policyContent, 'sample-soc2-policy.md');
    }
    /**
     * Create a sample ISO 27001 policy
     */
    createSampleISO27001Policy() {
        const policyContent = `# ISO 27001 Information Security Policy

**Version:** 2.0
**Status:** Active
**Owner:** CISO
**Department:** Information Security

## Purpose

This policy defines the organization's approach to information security management in accordance with ISO 27001 standards.

## Requirements

1. Information security objectives must be defined
2. Risk assessments must be conducted annually
3. Asset inventory must be maintained
4. Access control policy must be documented
5. Cryptographic controls must be used for sensitive data
6. Incident management procedures must be in place

## Controls

A.5 - Information Security Policies
- Implementation: Annual policy review

A.6 - Organization of Information Security
- Implementation: Defined roles and responsibilities

A.7 - Human Resource Security
- Implementation: Background checks and security training

A.8 - Asset Management
- Implementation: Asset classification and labeling
`;
        return this.parseMarkdown(policyContent, 'sample-iso27001-policy.md');
    }
    parseRequirements(reqs) {
        return reqs.map((req) => ({
            id: req.id || uuidv4(),
            description: req.description || '',
            category: req.category || 'General',
            mandatory: req.mandatory ?? true,
            relatedControls: req.relatedControls || [],
            severity: this.normalizeSeverity(req.severity || 'medium')
        }));
    }
    parseControls(ctrls) {
        return ctrls.map((ctrl) => ({
            id: ctrl.id || uuidv4(),
            name: ctrl.name || '',
            description: ctrl.description || '',
            implementation: ctrl.implementation || '',
            tested: ctrl.tested ?? false,
            lastTested: ctrl.lastTested ? new Date(ctrl.lastTested) : undefined,
            testResult: ctrl.testResult || 'not_tested'
        }));
    }
    normalizeFramework(framework) {
        const normalized = framework.toUpperCase().replace(/\s/g, '');
        switch (normalized) {
            case 'SOC2':
            case 'SOC-2':
                return 'SOC2';
            case 'ISO27001':
            case 'ISO-27001':
                return 'ISO27001';
            case 'HIPAA':
                return 'HIPAA';
            case 'GDPR':
                return 'GDPR';
            case 'PCI-DSS':
            case 'PCIDSS':
                return 'PCI-DSS';
            default:
                return 'CUSTOM';
        }
    }
    normalizeStatus(status) {
        const normalized = status.toLowerCase();
        if (normalized.includes('active'))
            return 'active';
        if (normalized.includes('draft'))
            return 'draft';
        if (normalized.includes('archive'))
            return 'archived';
        if (normalized.includes('super'))
            return 'superseded';
        return 'draft';
    }
    normalizeSeverity(severity) {
        const normalized = severity.toLowerCase();
        if (normalized.includes('critical'))
            return 'critical';
        if (normalized.includes('high'))
            return 'high';
        if (normalized.includes('medium'))
            return 'medium';
        if (normalized.includes('low'))
            return 'low';
        return 'info';
    }
    getPolicy(id) {
        return this.policies.get(id);
    }
    getAllPolicies() {
        return Array.from(this.policies.values());
    }
    getPoliciesByFramework(framework) {
        return this.getAllPolicies().filter(p => p.framework === framework);
    }
    getActivePolicies() {
        return this.getAllPolicies().filter(p => p.status === 'active');
    }
    deletePolicy(id) {
        return this.policies.delete(id);
    }
}
export default PolicyParser;
//# sourceMappingURL=policy-parser.js.map