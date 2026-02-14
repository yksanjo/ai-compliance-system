import { Playbook, Incident, IncidentEvent, Violation } from '../types/index.js';
export declare class SOARAutomation {
    private playbooks;
    private incidents;
    private executionHistory;
    constructor();
    /**
     * Initialize default SOAR playbooks
     */
    private initializeDefaultPlaybooks;
    /**
     * Execute playbooks for a violation
     */
    executePlaybooks(violation: Violation): Promise<Incident[]>;
    /**
     * Check if playbook should trigger for a violation
     */
    private shouldTrigger;
    /**
     * Execute a single playbook
     */
    private executePlaybook;
    /**
     * Execute a single step
     */
    private executeStep;
    /**
     * Execute action step
     */
    private executeAction;
    /**
     * Execute notification step
     */
    private executeNotification;
    /**
     * Execute delay step
     */
    private executeDelay;
    /**
     * Execute condition step
     */
    private executeCondition;
    /**
     * Execute remediation step
     */
    private executeRemediation;
    /**
     * Create incident from violation
     */
    private createIncidentFromViolation;
    /**
     * Convert severity to priority
     */
    private severityToPriority;
    /**
     * Add event to incident timeline
     */
    addIncidentEvent(incident: Incident, type: IncidentEvent['type'], description: string, actor?: string, data?: Record<string, unknown>): void;
    /**
     * Get incident by ID
     */
    getIncident(id: string): Incident | undefined;
    /**
     * Get all incidents
     */
    getAllIncidents(): Incident[];
    /**
     * Get incidents by status
     */
    getIncidentsByStatus(status: Incident['status']): Incident[];
    /**
     * Update incident
     */
    updateIncident(id: string, updates: Partial<Incident>): Incident | undefined;
    /**
     * Add playbook
     */
    addPlaybook(playbook: Playbook): void;
    /**
     * Get playbook by ID
     */
    getPlaybook(id: string): Playbook | undefined;
    /**
     * Get all playbooks
     */
    getAllPlaybooks(): Playbook[];
    /**
     * Enable/disable playbook
     */
    togglePlaybook(id: string, enabled: boolean): void;
    /**
     * Delete playbook
     */
    deletePlaybook(id: string): boolean;
    /**
     * Get execution history
     */
    getExecutionHistory(limit?: number): {
        playbookId: string;
        executedAt: Date;
        result: 'success' | 'failure';
    }[];
    /**
     * Get SOAR statistics
     */
    getStats(): {
        totalPlaybooks: number;
        enabledPlaybooks: number;
        totalIncidents: number;
        openIncidents: number;
        closedIncidents: number;
        recentExecutions: number;
    };
}
export default SOARAutomation;
//# sourceMappingURL=soar-automation.d.ts.map