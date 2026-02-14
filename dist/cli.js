#!/usr/bin/env node
import { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { ComplianceAgent } from './core/index.js';
import * as fs from 'fs';
import * as path from 'path';
const program = new Command();
// Initialize the agent
const agent = new ComplianceAgent('org-001', 'Demo Organization');
program
    .name('compliance-agent')
    .description('AI Compliance Automation System - Agent-native SOC2 compliance')
    .version('1.0.0');
// ============================================================================
// Interactive Mode
// ============================================================================
program
    .command('interactive')
    .alias('i')
    .description('Start interactive mode')
    .action(async () => {
    console.log(chalk.bold.cyan('\n🤖 AI Compliance Automation System\n'));
    console.log(chalk.gray('Agent-native SOC2 compliance automation\n'));
    while (true) {
        const { action } = await inquirer.prompt([
            {
                type: 'list',
                name: 'action',
                message: 'What would you like to do?',
                choices: [
                    '📋 Load Sample Policies',
                    '🌐 Add Infrastructure to Monitor',
                    '🔍 Run Compliance Scan',
                    '⚠️  View Violations',
                    '🚨 View Incidents',
                    '📊 Generate Report',
                    '🧠 Search Agent Memory',
                    '📈 View Statistics',
                    '❌ Exit'
                ]
            }
        ]);
        if (action === '❌ Exit') {
            console.log(chalk.yellow('\n👋 Goodbye!'));
            process.exit(0);
        }
        switch (action) {
            case '📋 Load Sample Policies':
                await loadSamplePolicies();
                break;
            case '🌐 Add Infrastructure to Monitor':
                await addInfrastructure();
                break;
            case '🔍 Run Compliance Scan':
                await runScan();
                break;
            case '⚠️  View Violations':
                await viewViolations();
                break;
            case '🚨 View Incidents':
                await viewIncidents();
                break;
            case '📊 Generate Report':
                await generateReport();
                break;
            case '🧠 Search Agent Memory':
                await searchMemory();
                break;
            case '📈 View Statistics':
                await viewStats();
                break;
        }
    }
});
async function loadSamplePolicies() {
    console.log(chalk.blue('\n📋 Loading sample policies...'));
    agent.createSamplePolicies();
    const policies = agent.getPolicies();
    console.log(chalk.green(`\n✅ Loaded ${policies.length} policies:`));
    for (const policy of policies) {
        console.log(chalk.gray(`   - ${policy.name} (${policy.framework}) - ${policy.status}`));
    }
}
async function addInfrastructure() {
    const { type } = await inquirer.prompt([
        {
            type: 'list',
            name: 'type',
            message: 'What type of asset?',
            choices: ['Domain', 'IP Address', 'SSL Certificate']
        }
    ]);
    const { identifier } = await inquirer.prompt([
        {
            type: 'input',
            name: 'identifier',
            message: `Enter the ${type.toLowerCase()}:`,
            validate: (input) => input.length > 0 || 'Please enter a value'
        }
    ]);
    try {
        let asset;
        if (type === 'Domain') {
            asset = await agent.addDomain(identifier);
        }
        else if (type === 'IP Address') {
            asset = await agent.addIP(identifier);
        }
        else {
            asset = await agent.addCertificate(identifier);
        }
        console.log(chalk.green(`\n✅ Added ${type}: ${identifier}`));
    }
    catch (error) {
        console.log(chalk.red(`\n❌ Error: ${error}`));
    }
}
async function runScan() {
    console.log(chalk.blue('\n🔍 Running compliance scan...\n'));
    // Ensure we have policies
    const policies = agent.getPolicies();
    if (policies.length === 0) {
        console.log(chalk.yellow('No policies loaded. Loading sample policies...'));
        agent.createSamplePolicies();
    }
    // Ensure we have some infrastructure
    const assets = agent.getMonitoredAssets();
    if (assets.length === 0) {
        console.log(chalk.yellow('No infrastructure monitored. Adding sample infrastructure...'));
        await agent.addDomain('example.com');
        await agent.addIP('8.8.8.8');
        await agent.addCertificate('example.com');
    }
    await agent.runFullScan();
    // Show results
    const violations = agent.getViolations();
    if (violations.length > 0) {
        console.log(chalk.red('\n⚠️  Violations found:'));
        for (const v of violations.slice(0, 5)) {
            console.log(chalk.gray(`   [${v.severity.toUpperCase()}] ${v.title}`));
        }
    }
}
async function viewViolations() {
    const violations = agent.getViolations();
    if (violations.length === 0) {
        console.log(chalk.yellow('\n⚠️  No violations found.'));
        return;
    }
    console.log(chalk.red(`\n⚠️  Found ${violations.length} violations:\n`));
    const { selected } = await inquirer.prompt([
        {
            type: 'list',
            name: 'selected',
            message: 'Select a violation to view details:',
            choices: violations.map((v, i) => ({
                name: `[${v.severity.toUpperCase()}] ${v.title}`,
                value: i
            }))
        }
    ]);
    const v = violations[selected];
    console.log(chalk.bold(`\n📋 ${v.title}\n`));
    console.log(chalk.gray(`   Policy: ${v.policyName}`));
    console.log(chalk.gray(`   Asset: ${v.assetType}: ${v.assetIdentifier}`));
    console.log(chalk.gray(`   Status: ${v.status}`));
    console.log(chalk.gray(`   Detected: ${v.detectedAt.toISOString()}`));
    console.log(chalk.gray(`\n   ${v.description}`));
}
async function viewIncidents() {
    const incidents = agent.getIncidents();
    if (incidents.length === 0) {
        console.log(chalk.yellow('\n🚨 No incidents found.'));
        return;
    }
    console.log(chalk.red(`\n🚨 Found ${incidents.length} incidents:\n`));
    for (const incident of incidents) {
        console.log(chalk.bold(`   ${incident.title}`));
        console.log(chalk.gray(`      Priority: ${incident.priority} | Status: ${incident.status}`));
    }
}
async function generateReport() {
    const { framework } = await inquirer.prompt([
        {
            type: 'list',
            name: 'framework',
            message: 'Select compliance framework:',
            choices: ['SOC2', 'ISO27001', 'HIPAA', 'GDPR', 'CUSTOM']
        }
    ]);
    const { type } = await inquirer.prompt([
        {
            type: 'list',
            name: 'type',
            message: 'Select report type:',
            choices: ['executive', 'detailed', 'gap_analysis', 'audit']
        }
    ]);
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const report = agent.generateReport({
        framework: framework,
        type: type,
        period: {
            start: thirtyDaysAgo,
            end: now
        }
    });
    console.log(chalk.green('\n✅ Report generated!'));
    console.log(chalk.gray(`\n   Framework: ${report.framework}`));
    console.log(chalk.gray(`   Type: ${report.type}`));
    console.log(chalk.gray(`   Compliance Score: ${report.summary.compliancePercentage}%`));
    console.log(chalk.gray(`   Risk Score: ${report.summary.riskScore}/100`));
    console.log(chalk.gray(`   Findings: ${report.findings.length}`));
    // Export options
    const { exportFormat } = await inquirer.prompt([
        {
            type: 'list',
            name: 'exportFormat',
            message: 'Export report as:',
            choices: ['Markdown', 'HTML', 'JSON', 'Skip']
        }
    ]);
    if (exportFormat !== 'Skip') {
        const { ReportGenerator } = await import('./core/report-generator.js');
        const generator = new ReportGenerator();
        let content;
        let ext;
        if (exportFormat === 'Markdown') {
            content = generator.exportToMarkdown(report);
            ext = 'md';
        }
        else if (exportFormat === 'HTML') {
            content = generator.exportToHTML(report);
            ext = 'html';
        }
        else {
            content = generator.exportToJSON(report);
            ext = 'json';
        }
        const filename = `compliance-report-${report.framework.toLowerCase()}-${Date.now()}.${ext}`;
        fs.writeFileSync(filename, content);
        console.log(chalk.green(`\n✅ Report exported to: ${filename}`));
    }
}
async function searchMemory() {
    const { query } = await inquirer.prompt([
        {
            type: 'input',
            name: 'query',
            message: 'Enter search query:'
        }
    ]);
    const results = agent.searchMemory(query);
    console.log(chalk.blue(`\n🔍 Search results for "${query}":\n`));
    if (results.length === 0) {
        console.log(chalk.yellow('   No results found.'));
        return;
    }
    for (const result of results.slice(0, 5)) {
        console.log(chalk.gray(`   [${result.type}] ${result.content.substring(0, 100)}...`));
    }
}
async function viewStats() {
    console.log(chalk.bold.cyan('\n📊 System Statistics\n'));
    const violationStats = agent.getViolationStats();
    console.log(chalk.bold('Violations:'));
    console.log(chalk.gray(`   Total: ${violationStats.total}`));
    console.log(chalk.gray(`   Open: ${violationStats.openCount}`));
    console.log(chalk.gray(`   Resolved: ${violationStats.resolvedCount}`));
    const soarStats = agent.getSOARStats();
    console.log(chalk.bold('\nSOAR:'));
    console.log(chalk.gray(`   Playbooks: ${soarStats.enabledPlaybooks}/${soarStats.totalPlaybooks}`));
    console.log(chalk.gray(`   Incidents: ${soarStats.openIncidents} open / ${soarStats.closedIncidents} closed`));
    const memoryStats = agent.getMemoryStats();
    console.log(chalk.bold('\nAgent Memory:'));
    console.log(chalk.gray(`   Total Entries: ${memoryStats.totalMemories}`));
    console.log(chalk.gray(`   By Type: ${JSON.stringify(memoryStats.byType)}`));
    const policies = agent.getPolicies();
    const assets = agent.getMonitoredAssets();
    console.log(chalk.bold('\nInfrastructure:'));
    console.log(chalk.gray(`   Policies: ${policies.length}`));
    console.log(chalk.gray(`   Monitored Assets: ${assets.length}`));
}
// ============================================================================
// Direct Commands
// ============================================================================
program
    .command('scan')
    .description('Run a full compliance scan')
    .option('-p, --policy <file>', 'Load policy from file')
    .option('-d, --domain <domain>', 'Add domain to monitor')
    .option('-i, --ip <ip>', 'Add IP to monitor')
    .option('-c, --cert <domain>', 'Add certificate to monitor')
    .action(async (options) => {
    console.log(chalk.blue('\n🔍 Running compliance scan...\n'));
    // Load policies
    if (options.policy) {
        try {
            await agent.loadPolicy(options.policy);
            console.log(chalk.green(`✅ Loaded policy: ${options.policy}`));
        }
        catch (error) {
            console.log(chalk.red(`❌ Error loading policy: ${error}`));
        }
    }
    else {
        agent.createSamplePolicies();
    }
    // Add infrastructure
    if (options.domain) {
        await agent.addDomain(options.domain);
    }
    if (options.ip) {
        await agent.addIP(options.ip);
    }
    if (options.cert) {
        await agent.addCertificate(options.cert);
    }
    await agent.runFullScan();
});
program
    .command('report')
    .description('Generate a compliance report')
    .requiredOption('-f, --framework <framework>', 'Compliance framework (SOC2, ISO27001, etc.)')
    .option('-t, --type <type>', 'Report type (executive, detailed, gap_analysis, audit)', 'detailed')
    .option('-o, --output <file>', 'Output file')
    .action(async (options) => {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const report = agent.generateReport({
        framework: options.framework,
        type: options.type,
        period: {
            start: thirtyDaysAgo,
            end: now
        }
    });
    const { ReportGenerator } = await import('./core/report-generator.js');
    const generator = new ReportGenerator();
    let content;
    let ext;
    if (options.output) {
        ext = path.extname(options.output).slice(1);
    }
    else {
        ext = 'md';
    }
    if (ext === 'html') {
        content = generator.exportToHTML(report);
    }
    else if (ext === 'json') {
        content = generator.exportToJSON(report);
    }
    else {
        content = generator.exportToMarkdown(report);
    }
    if (options.output) {
        fs.writeFileSync(options.output, content);
        console.log(chalk.green(`✅ Report saved to: ${options.output}`));
    }
    else {
        console.log(content);
    }
});
program
    .command('violations')
    .description('List all violations')
    .option('-s, --status <status>', 'Filter by status')
    .option('-v, --severity <severity>', 'Filter by severity')
    .action((options) => {
    let violations = agent.getViolations();
    if (options.status) {
        violations = violations.filter(v => v.status === options.status);
    }
    if (options.severity) {
        violations = violations.filter(v => v.severity === options.severity);
    }
    console.log(chalk.red(`\n⚠️  ${violations.length} violations:\n`));
    for (const v of violations) {
        const severityColor = v.severity === 'critical' ? chalk.red :
            v.severity === 'high' ? chalk.yellow : chalk.gray;
        console.log(severityColor(`[${v.severity.toUpperCase()}] ${v.title}`));
        console.log(chalk.gray(`   ${v.assetType}: ${v.assetIdentifier} | ${v.status}`));
    }
});
program
    .command('policies')
    .description('List all policies')
    .action(() => {
    const policies = agent.getPolicies();
    console.log(chalk.blue(`\n📋 ${policies.length} policies:\n`));
    for (const p of policies) {
        console.log(chalk.bold(`${p.name}`));
        console.log(chalk.gray(`   Framework: ${p.framework} | Status: ${p.status} | Version: ${p.version}`));
        console.log(chalk.gray(`   Requirements: ${p.requirements.length} | Controls: ${p.controls.length}`));
    }
});
program
    .command('incidents')
    .description('List all incidents')
    .action(() => {
    const incidents = agent.getIncidents();
    console.log(chalk.red(`\n🚨 ${incidents.length} incidents:\n`));
    for (const incident of incidents) {
        console.log(chalk.bold(`${incident.title}`));
        console.log(chalk.gray(`   Priority: ${incident.priority} | Status: ${incident.status} | Violations: ${incident.violationIds.length}`));
    }
});
// Parse commands
program.parse();
//# sourceMappingURL=cli.js.map