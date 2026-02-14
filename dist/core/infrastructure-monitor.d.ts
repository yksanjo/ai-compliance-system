import { MonitoredAsset, DomainRecord, IPRecord, CertificateInfo } from '../types/index.js';
export declare class InfrastructureMonitor {
    private assets;
    private domainCache;
    private ipCache;
    private certCache;
    /**
     * Add a domain to monitoring
     */
    addDomain(domain: string, organizationId: string): Promise<MonitoredAsset>;
    /**
     * Add an IP to monitoring
     */
    addIP(ip: string, organizationId: string): Promise<MonitoredAsset>;
    /**
     * Add a certificate to monitoring
     */
    addCertificate(domain: string, organizationId: string): Promise<MonitoredAsset>;
    /**
     * Lookup domain DNS records
     */
    lookupDomain(domain: string): Promise<DomainRecord>;
    /**
     * Lookup IP information
     */
    lookupIP(ip: string): Promise<IPRecord>;
    /**
     * Lookup SSL/TLS certificate information
     */
    lookupCertificate(domain: string): Promise<CertificateInfo>;
    /**
     * Check certificate expiration
     */
    checkCertificateExpiry(cert: CertificateInfo): {
        isExpiring: boolean;
        daysLeft: number;
        severity: 'critical' | 'high' | 'medium' | 'low';
    };
    /**
     * Check if domain has proper security records
     */
    checkDomainSecurity(domain: string): {
        hasSPF: boolean;
        hasDMARC: boolean;
        hasDKIM: boolean;
        issues: string[];
    };
    /**
     * Refresh all monitored assets
     */
    refreshAll(): Promise<void>;
    /**
     * Get all monitored assets
     */
    getAssets(): MonitoredAsset[];
    /**
     * Get asset by ID
     */
    getAsset(id: string): MonitoredAsset | undefined;
    /**
     * Get cached domain info
     */
    getDomainInfo(domain: string): DomainRecord | undefined;
    /**
     * Get cached IP info
     */
    getIPInfo(ip: string): IPRecord | undefined;
    /**
     * Get cached certificate info
     */
    getCertificateInfo(domain: string): CertificateInfo | undefined;
    /**
     * Remove an asset from monitoring
     */
    removeAsset(id: string): boolean;
    /**
     * Helper to resolve DNS with promises
     */
    private resolveDNS;
    /**
     * Reverse DNS lookup helper
     */
    private reverseLookup;
    /**
     * Check if IP is in private range
     */
    private isPrivateIP;
    /**
     * Create sample monitored infrastructure
     */
    createSampleInfrastructure(orgId: string): Promise<void>;
}
export default InfrastructureMonitor;
//# sourceMappingURL=infrastructure-monitor.d.ts.map