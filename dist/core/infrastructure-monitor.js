import { v4 as uuidv4 } from 'uuid';
// Simple DNS lookup using native resolver
import * as dns from 'dns';
import * as net from 'net';
export class InfrastructureMonitor {
    assets = new Map();
    domainCache = new Map();
    ipCache = new Map();
    certCache = new Map();
    /**
     * Add a domain to monitoring
     */
    async addDomain(domain, organizationId) {
        const id = uuidv4();
        const asset = {
            id,
            type: 'domain',
            identifier: domain,
            organizationId,
            lastChecked: new Date(),
            status: 'active',
            metadata: {}
        };
        this.assets.set(id, asset);
        // Initial lookup
        try {
            const domainInfo = await this.lookupDomain(domain);
            this.domainCache.set(domain, domainInfo);
        }
        catch (error) {
            asset.status = 'unknown';
            console.error(`Failed to lookup domain ${domain}:`, error);
        }
        return asset;
    }
    /**
     * Add an IP to monitoring
     */
    async addIP(ip, organizationId) {
        const id = uuidv4();
        const asset = {
            id,
            type: 'ip',
            identifier: ip,
            organizationId,
            lastChecked: new Date(),
            status: 'active',
            metadata: {}
        };
        this.assets.set(id, asset);
        // Initial lookup
        try {
            const ipInfo = await this.lookupIP(ip);
            this.ipCache.set(ip, ipInfo);
        }
        catch (error) {
            asset.status = 'unknown';
            console.error(`Failed to lookup IP ${ip}:`, error);
        }
        return asset;
    }
    /**
     * Add a certificate to monitoring
     */
    async addCertificate(domain, organizationId) {
        const id = uuidv4();
        const asset = {
            id,
            type: 'certificate',
            identifier: domain,
            organizationId,
            lastChecked: new Date(),
            status: 'active',
            metadata: {}
        };
        this.assets.set(id, asset);
        // Initial certificate lookup
        try {
            const certInfo = await this.lookupCertificate(domain);
            this.certCache.set(domain, certInfo);
        }
        catch (error) {
            asset.status = 'unknown';
            console.error(`Failed to lookup certificate for ${domain}:`, error);
        }
        return asset;
    }
    /**
     * Lookup domain DNS records
     */
    async lookupDomain(domain) {
        const dnsRecords = [];
        // Resolve A records
        try {
            const aRecords = await this.resolveDNS(domain, 'A');
            for (const ip of aRecords) {
                dnsRecords.push({
                    type: 'A',
                    name: domain,
                    value: ip,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // A record not found
        }
        // Resolve AAAA records
        try {
            const aaaaRecords = await this.resolveDNS(domain, 'AAAA');
            for (const ip of aaaaRecords) {
                dnsRecords.push({
                    type: 'AAAA',
                    name: domain,
                    value: ip,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // AAAA record not found
        }
        // Resolve CNAME records
        try {
            const cnameRecords = await this.resolveDNS(domain, 'CNAME');
            for (const cname of cnameRecords) {
                dnsRecords.push({
                    type: 'CNAME',
                    name: domain,
                    value: cname,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // CNAME not found
        }
        // Resolve MX records
        try {
            const mxRecords = await this.resolveDNS(domain, 'MX');
            for (const mx of mxRecords) {
                dnsRecords.push({
                    type: 'MX',
                    name: domain,
                    value: mx,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // MX not found
        }
        // Resolve TXT records
        try {
            const txtRecords = await this.resolveDNS(domain, 'TXT');
            for (const txt of txtRecords) {
                dnsRecords.push({
                    type: 'TXT',
                    name: domain,
                    value: txt,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // TXT not found
        }
        // Resolve NS records
        try {
            const nsRecords = await this.resolveDNS(domain, 'NS');
            for (const ns of nsRecords) {
                dnsRecords.push({
                    type: 'NS',
                    name: domain,
                    value: ns,
                    ttl: 300
                });
            }
        }
        catch (e) {
            // NS not found
        }
        return {
            domain,
            registrar: 'Unknown', // Would need WHOIS API for this
            registrationDate: new Date(),
            expirationDate: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
            nameservers: dnsRecords.filter(r => r.type === 'NS').map(r => r.value),
            dnsRecords,
            status: ['ok']
        };
    }
    /**
     * Lookup IP information
     */
    async lookupIP(ip) {
        const version = net.isIP(ip);
        if (!version) {
            throw new Error(`Invalid IP address: ${ip}`);
        }
        // Basic IP info (would need external API for full ASN/geolocation)
        const ipInfo = {
            ip,
            version,
            asn: 0,
            asnOrg: 'Unknown',
            country: 'Unknown',
            city: 'Unknown',
            isp: 'Unknown',
            isProxy: false,
            isVPN: false,
            isTor: false,
            reputation: 'unknown'
        };
        // Try to get hostname reverse lookup
        try {
            const hostnames = await this.reverseLookup(ip);
            if (hostnames && hostnames.length > 0) {
                ipInfo.hostname = hostnames[0];
            }
        }
        catch (e) {
            // No reverse DNS
        }
        // Check if IP is in private range
        if (this.isPrivateIP(ip)) {
            ipInfo.isPrivate = true;
            ipInfo.reputation = 'good';
        }
        // For public IPs, we would call an external API (like ipwhois, ipinfo)
        // For now, return basic info
        return ipInfo;
    }
    /**
     * Lookup SSL/TLS certificate information
     */
    async lookupCertificate(domain) {
        // This is a simplified version - in production you'd use node-fetch to connect
        // to the domain's port 443 and parse the certificate
        const certInfo = {
            domain,
            issuer: 'Unknown',
            subject: domain,
            validFrom: new Date(),
            validTo: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000), // 90 days
            serialNumber: '',
            signatureAlgorithm: 'sha256WithRSAEncryption',
            keyAlgorithm: 'RSA',
            keySize: 2048,
            isValid: true,
            daysUntilExpiry: 90
        };
        // In production, use:
        // const cert = await tls.connect(443, domain).getPeerCertificate();
        // Or use a library like node-fetch with TLS inspection
        return certInfo;
    }
    /**
     * Check certificate expiration
     */
    checkCertificateExpiry(cert) {
        const daysLeft = cert.daysUntilExpiry;
        if (daysLeft <= 7) {
            return { isExpiring: true, daysLeft, severity: 'critical' };
        }
        else if (daysLeft <= 30) {
            return { isExpiring: true, daysLeft, severity: 'high' };
        }
        else if (daysLeft <= 60) {
            return { isExpiring: true, daysLeft, severity: 'medium' };
        }
        else {
            return { isExpiring: false, daysLeft, severity: 'low' };
        }
    }
    /**
     * Check if domain has proper security records
     */
    checkDomainSecurity(domain) {
        const domainRecord = this.domainCache.get(domain);
        if (!domainRecord) {
            return { hasSPF: false, hasDMARC: false, hasDKIM: false, issues: ['Domain not found in cache'] };
        }
        const txtRecords = domainRecord.dnsRecords.filter(r => r.type === 'TXT');
        const issues = [];
        const hasSPF = txtRecords.some(r => r.value.includes('v=spf1'));
        const hasDMARC = txtRecords.some(r => r.value.includes('v=DMARC1'));
        const hasDKIM = txtRecords.some(r => r.value.includes('v=DKIM1'));
        if (!hasSPF)
            issues.push('Missing SPF record');
        if (!hasDMARC)
            issues.push('Missing DMARC record');
        if (!hasDKIM)
            issues.push('Missing DKIM record');
        return { hasSPF, hasDMARC, hasDKIM, issues };
    }
    /**
     * Refresh all monitored assets
     */
    async refreshAll() {
        for (const asset of this.assets.values()) {
            try {
                asset.lastChecked = new Date();
                if (asset.type === 'domain') {
                    const domainInfo = await this.lookupDomain(asset.identifier);
                    this.domainCache.set(asset.identifier, domainInfo);
                }
                else if (asset.type === 'ip') {
                    const ipInfo = await this.lookupIP(asset.identifier);
                    this.ipCache.set(asset.identifier, ipInfo);
                }
                else if (asset.type === 'certificate') {
                    const certInfo = await this.lookupCertificate(asset.identifier);
                    this.certCache.set(asset.identifier, certInfo);
                }
            }
            catch (error) {
                console.error(`Failed to refresh asset ${asset.identifier}:`, error);
            }
        }
    }
    /**
     * Get all monitored assets
     */
    getAssets() {
        return Array.from(this.assets.values());
    }
    /**
     * Get asset by ID
     */
    getAsset(id) {
        return this.assets.get(id);
    }
    /**
     * Get cached domain info
     */
    getDomainInfo(domain) {
        return this.domainCache.get(domain);
    }
    /**
     * Get cached IP info
     */
    getIPInfo(ip) {
        return this.ipCache.get(ip);
    }
    /**
     * Get cached certificate info
     */
    getCertificateInfo(domain) {
        return this.certCache.get(domain);
    }
    /**
     * Remove an asset from monitoring
     */
    removeAsset(id) {
        const asset = this.assets.get(id);
        if (asset) {
            // Clean up caches
            if (asset.type === 'domain') {
                this.domainCache.delete(asset.identifier);
            }
            else if (asset.type === 'ip') {
                this.ipCache.delete(asset.identifier);
            }
            else if (asset.type === 'certificate') {
                this.certCache.delete(asset.identifier);
            }
            return this.assets.delete(id);
        }
        return false;
    }
    /**
     * Helper to resolve DNS with promises
     */
    resolveDNS(domain, type) {
        return new Promise((resolve, reject) => {
            const resolver = type === 'MX' ? dns.resolveMx : dns.resolve;
            resolver(domain, (err, addresses) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(addresses);
                }
            });
        });
    }
    /**
     * Reverse DNS lookup helper
     */
    reverseLookup(ip) {
        return new Promise((resolve, reject) => {
            dns.reverse(ip, (err, hostnames) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve(hostnames);
                }
            });
        });
    }
    /**
     * Check if IP is in private range
     */
    isPrivateIP(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4)
            return false;
        // 10.0.0.0/8
        if (parts[0] === 10)
            return true;
        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31)
            return true;
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168)
            return true;
        return false;
    }
    /**
     * Create sample monitored infrastructure
     */
    async createSampleInfrastructure(orgId) {
        // Sample domains
        await this.addDomain('example.com', orgId);
        await this.addDomain('api.example.com', orgId);
        await this.addDomain('mail.example.com', orgId);
        // Sample IPs
        await this.addIP('8.8.8.8', orgId);
        await this.addIP('1.1.1.1', orgId);
        await this.addIP('192.168.1.1', orgId);
        // Sample certificates
        await this.addCertificate('example.com', orgId);
        await this.addCertificate('api.example.com', orgId);
    }
}
export default InfrastructureMonitor;
//# sourceMappingURL=infrastructure-monitor.js.map