import { v4 as uuidv4 } from 'uuid';
export class SOARAutomation {
    playbooks = new Map();
    incidents = new Map();
    executionHistory = [];
    constructor() {
        this.initializeDefaultPlaybooks();
    }
    /**
     * Initialize default SOAR playbooks
     */
    initializeDefaultPlaybooks() {
        // Critical violation alert playbook
        this.playbooks.set('critical-alert', {
            id: 'critical-alert',
            name: 'Critical Violation Alert',
            description: 'Automatically alert on critical severity violations',
            trigger: {
                type: 'violation',
                conditions: {
                    severity: ['critical']
                }
            },
            steps: [
                {
                    id: 'step-1',
                    name: 'Create Incident',
                    type: 'action',
                    config: {
                        action: 'create_incident'
                    },
                    onSuccess: 'step-2',
                    onFailure: 'end'
                },
                {
                    id: 'step-2',
                    name: 'Send Slack Alert',
                    type: 'notification',
                    config: {
                        notification: {
                            channel: 'slack',
                            template: '🚨 Critical Violation Detected: {{violation.title}}',
                            recipients: ['#security-alerts']
                        }
                    },
                    onSuccess: 'step-3',
                    onFailure: 'end'
                },
                {
                    id: 'step-3',
                    name: 'Escalate to On-Call',
                    type: 'action',
                    config: {
                        action: 'escalate'
                    }
                }
            ],
            enabled: true
        });
        // High severity playbook
        this.playbooks.set('high-severity-response', {
            id: 'high-severity-response',
            name: 'High Severity Response',
            description: 'Automated response for high severity violations',
            trigger: {
                type: 'violation',
                conditions: {
                    severity: ['high']
                }
            },
            steps: [
                {
                    id: 'step-1',
                    name: 'Create Incident',
                    type: 'action',
                    config: {
                        action: 'create_incident'
                    }
                },
                {
                    id: 'step-2',
                    name: 'Send Notification',
                    type: 'notification',
                    config: {
                        notification: {
                            channel: 'slack',
                            template: '⚠️ High Severity Violation: {{violation.title}}',
                            recipients: ['#security-team']
                        }
                    }
                }
            ],
            enabled: true
        });
        // Certificate expiry playbook
        this.playbooks.set('cert-expiry-alert', {
            id: 'cert-expiry-alert',
            name: 'Certificate Expiry Alert',
            description: 'Alert when certificates are expiring',
            trigger: {
                type: 'violation',
                conditions: {
                    severity: ['critical', 'high']
                }
            },
            steps: [
                {
                    id: 'step-1',
                    name: 'Create Incident',
                    type: 'action',
                    config: {
                        action: 'create_incident'
                    }
                },
                {
                    id: 'step-2',
                    name: 'Wait for Acknowledgment',
                    type: 'delay',
                    config: {
                        delay: {
                            seconds: 300 // 5 minutes
                        }
                    }
                },
                {
                    id: 'step-3',
                    name: 'Escalate if Unacknowledged',
                    type: 'condition',
                    config: {
                        condition: {
                            field: 'acknowledged',
                            operator: 'equals',
                            value: false
                        }
                    },
                    onFailure: 'step-4'
                },
                {
                    id: 'step-4',
                    name: 'Send Escalation',
                    type: 'notification',
                    config: {
                        notification: {
                            channel: 'slack',
                            template: '🔔 Certificate Expiry Unacknowledged: {{violation.title}}',
                            recipients: ['#security-alerts']
                        }
                    }
                }
            ],
            enabled: true
        });
    }
    /**
     * Execute playbooks for a violation
     */
    async executePlaybooks(violation) {
        const triggeredIncidents = [];
        for (const playbook of this.playbooks.values()) {
            if (!playbook.enabled)
                continue;
            if (this.shouldTrigger(playbook, violation)) {
                const incident = await this.executePlaybook(playbook, violation);
                if (incident) {
                    triggeredIncidents.push(incident);
                }
            }
        }
        return triggeredIncidents;
    }
    /**
     * Check if playbook should trigger for a violation
     */
    shouldTrigger(playbook, violation) {
        if (playbook.trigger.type !== 'violation')
            return false;
        const conditions = playbook.trigger.conditions;
        // Check severity conditions
        if (conditions.severity && conditions.severity.length > 0) {
            if (!conditions.severity.includes(violation.severity)) {
                return false;
            }
        }
        // Check asset type conditions
        if (conditions.assetType && conditions.assetType.length > 0) {
            if (!conditions.assetType.includes(violation.assetType)) {
                return false;
            }
        }
        // Check policy conditions
        if (conditions.policyId) {
            if (violation.policyId !== conditions.policyId) {
                return false;
            }
        }
        return true;
    }
    /**
     * Execute a single playbook
     */
    async executePlaybook(playbook, violation) {
        try {
            let currentStepId = playbook.steps[0]?.id;
            let incident = null;
            while (currentStepId) {
                const step = playbook.steps.find(s => s.id === currentStepId);
                if (!step)
                    break;
                const result = await this.executeStep(step, violation, incident);
                if (result.success) {
                    currentStepId = step.onSuccess;
                }
                else {
                    currentStepId = step.onFailure;
                }
                // Create incident if action step
                if (step.type === 'action' && step.config.action === 'create_incident') {
                    incident = result.data;
                }
            }
            this.executionHistory.push({
                playbookId: playbook.id,
                executedAt: new Date(),
                result: 'success'
            });
            playbook.lastRun = new Date();
            return incident;
        }
        catch (error) {
            this.executionHistory.push({
                playbookId: playbook.id,
                executedAt: new Date(),
                result: 'failure'
            });
            console.error(`Playbook execution failed: ${playbook.name}`, error);
            return null;
        }
    }
    /**
     * Execute a single step
     */
    async executeStep(step, violation, incident) {
        switch (step.type) {
            case 'action':
                return this.executeAction(step, violation, incident);
            case 'notification':
                return this.executeNotification(step, violation, incident);
            case 'delay':
                return this.executeDelay(step);
            case 'condition':
                return this.executeCondition(step, violation, incident);
            case 'remediation':
                return this.executeRemediation(step, violation, incident);
            default:
                return { success: true };
        }
    }
    /**
     * Execute action step
     */
    async executeAction(step, violation, incident) {
        const action = step.config.action;
        switch (action) {
            case 'create_incident': {
                const newIncident = this.createIncidentFromViolation(violation);
                return { success: true, data: newIncident };
            }
            case 'update_status': {
                if (incident) {
                    incident.status = 'investigating';
                    incident.updatedAt = new Date();
                    this.addIncidentEvent(incident, 'status_change', 'Status updated to investigating');
                }
                return { success: !!incident };
            }
            case 'assign': {
                if (incident) {
                    incident.assignee = 'security-team';
                    incident.updatedAt = new Date();
                    this.addIncidentEvent(incident, 'assignment', 'Assigned to security team');
                }
                return { success: !!incident };
            }
            case 'escalate': {
                if (incident) {
                    incident.priority = 'P1';
                    incident.updatedAt = new Date();
                    this.addIncidentEvent(incident, 'escalation', 'Incident escalated to P1');
                }
                return { success: !!incident };
            }
            default:
                return { success: false };
        }
    }
    /**
     * Execute notification step
     */
    async executeNotification(step, violation, incident) {
        const notification = step.config.notification;
        if (!notification)
            return { success: false };
        // Format message with variables
        let message = notification.template
            .replace('{{violation.title}}', violation.title)
            .replace('{{violation.description}}', violation.description)
            .replace('{{violation.severity}}', violation.severity)
            .replace('{{incident.id}}', incident && incident.id ? incident.id : 'N/A');
        // In production, integrate with actual notification channels
        switch (notification.channel) {
            case 'slack':
                console.log(`[SLACK] ${message} -> ${notification.recipients.join(', ')}`);
                break;
            case 'email':
                console.log(`[EMAIL] ${message} -> ${notification.recipients.join(', ')}`);
                break;
            case 'jira':
                console.log(`[JIRA] Creating ticket: ${message}`);
                break;
            case 'pagerduty':
                console.log(`[PAGERDUTY] Triggering: ${message}`);
                break;
            case 'webhook':
                console.log(`[WEBHOOK] Sending: ${message}`);
                break;
        }
        return { success: true };
    }
    /**
     * Execute delay step
     */
    async executeDelay(step) {
        const delay = step.config.delay;
        if (!delay)
            return { success: false };
        console.log(`[DELAY] Waiting ${delay.seconds} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay.seconds * 1000));
        return { success: true };
    }
    /**
     * Execute condition step
     */
    async executeCondition(step, violation, incident) {
        const condition = step.config.condition;
        if (!condition)
            return { success: false };
        // Evaluate condition (simplified)
        let value;
        switch (condition.field) {
            case 'acknowledged':
                value = incident ? !!incident.assignee : false;
                break;
            case 'severity':
                value = violation.severity;
                break;
            default:
                value = undefined;
        }
        const matches = value === condition.value;
        return { success: matches };
    }
    /**
     * Execute remediation step
     */
    async executeRemediation(step, violation, incident) {
        const remediation = step.config.remediation;
        if (!remediation)
            return { success: false };
        console.log(`[REMEDIATION] Would execute: ${remediation.script}`);
        // In production, execute actual remediation scripts
        return { success: true };
    }
    /**
     * Create incident from violation
     */
    createIncidentFromViolation(violation) {
        const priority = this.severityToPriority(violation.severity);
        const incident = {
            id: uuidv4(),
            title: violation.title,
            description: violation.description,
            severity: violation.severity,
            status: 'open',
            priority,
            reporter: 'ComplianceAgent',
            violationIds: [violation.id],
            timeline: [
                {
                    id: uuidv4(),
                    type: 'created',
                    description: 'Incident created from violation',
                    actor: 'ComplianceAgent',
                    timestamp: new Date()
                }
            ],
            createdAt: new Date(),
            updatedAt: new Date()
        };
        this.incidents.set(incident.id, incident);
        return incident;
    }
    /**
     * Convert severity to priority
     */
    severityToPriority(severity) {
        switch (severity) {
            case 'critical':
                return 'P1';
            case 'high':
                return 'P2';
            case 'medium':
                return 'P3';
            case 'low':
            case 'info':
                return 'P4';
        }
    }
    /**
     * Add event to incident timeline
     */
    addIncidentEvent(incident, type, description, actor = 'ComplianceAgent', data) {
        const event = {
            id: uuidv4(),
            type,
            description,
            actor,
            timestamp: new Date(),
            data
        };
        incident.timeline.push(event);
        incident.updatedAt = new Date();
    }
    /**
     * Get incident by ID
     */
    getIncident(id) {
        return this.incidents.get(id);
    }
    /**
     * Get all incidents
     */
    getAllIncidents() {
        return Array.from(this.incidents.values());
    }
    /**
     * Get incidents by status
     */
    getIncidentsByStatus(status) {
        return this.getAllIncidents().filter(i => i.status === status);
    }
    /**
     * Update incident
     */
    updateIncident(id, updates) {
        const incident = this.incidents.get(id);
        if (!incident)
            return undefined;
        Object.assign(incident, updates);
        incident.updatedAt = new Date();
        return incident;
    }
    /**
     * Add playbook
     */
    addPlaybook(playbook) {
        this.playbooks.set(playbook.id, playbook);
    }
    /**
     * Get playbook by ID
     */
    getPlaybook(id) {
        return this.playbooks.get(id);
    }
    /**
     * Get all playbooks
     */
    getAllPlaybooks() {
        return Array.from(this.playbooks.values());
    }
    /**
     * Enable/disable playbook
     */
    togglePlaybook(id, enabled) {
        const playbook = this.playbooks.get(id);
        if (playbook) {
            playbook.enabled = enabled;
        }
    }
    /**
     * Delete playbook
     */
    deletePlaybook(id) {
        return this.playbooks.delete(id);
    }
    /**
     * Get execution history
     */
    getExecutionHistory(limit = 10) {
        return this.executionHistory.slice(-limit);
    }
    /**
     * Get SOAR statistics
     */
    getStats() {
        const incidents = this.getAllIncidents();
        return {
            totalPlaybooks: this.playbooks.size,
            enabledPlaybooks: Array.from(this.playbooks.values()).filter(p => p.enabled).length,
            totalIncidents: incidents.length,
            openIncidents: incidents.filter(i => i.status !== 'closed').length,
            closedIncidents: incidents.filter(i => i.status === 'closed').length,
            recentExecutions: this.executionHistory.length
        };
    }
}
export default SOARAutomation;
//# sourceMappingURL=soar-automation.js.map