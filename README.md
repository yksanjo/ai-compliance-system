# AI Compliance Automation System 🤖

Agent-native SOC2 compliance automation that parses company policies, monitors infrastructure, detects violations, and auto-generates compliance reports.

## Features

### 🔍 Policy Parser (Doctra-inspired)
- Parse company policies from Markdown, JSON, and YAML formats
- Extract compliance requirements, controls, and obligations
- Auto-detect compliance frameworks (SOC2, ISO 27001, HIPAA, GDPR)
- Store parsed policies in agent memory for semantic retrieval

### 🌐 Infrastructure Monitor
- **DNS Monitoring**: Track domain registrations, DNS records, TTL changes
- **IP Monitoring**: Track IP ranges, reputation, proxy/VPN detection
- **Certificate Monitoring**: SSL/TLS certificate expiration tracking
- **Security Record Checking**: SPF, DKIM, DMARC validation

### ⚠️ Violation Detection Engine
- Real-time policy vs. infrastructure comparison
- Rule-based detection with severity scoring
- Automatic evidence collection
- Remediation tracking

### 🧠 Agent Memory
- Vector-based semantic storage for policies
- Conversation history and context retention
- Similarity search for compliance queries
- Knowledge base for compliance patterns

### 🚀 SOAR Automation
- Automated response workflows for violations
- Incident creation and triage
- Playbook execution (Slack, Email, JIRA, PagerDuty)
- Escalation and assignment automation

### 📊 Compliance Reports
- Automated SOC2, ISO 27001, HIPAA report generation
- Evidence collection and mapping
- Export to Markdown, HTML, or JSON
- Executive summaries with risk scoring

## Installation

```bash
cd ai-compliance-system
npm install
```

## Usage

### Interactive Mode

```bash
npm run dev -- interactive
# or
npm run dev -- i
```

### Command Line

```bash
# Run a compliance scan
npm run dev -- scan -d example.com -c example.com

# Generate a SOC2 report
npm run dev -- report -f SOC2 -t detailed -o report.md

# List violations
npm run dev -- violations

# List policies
npm run dev -- policies

# List incidents
npm run dev -- incidents
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    ComplianceAgent Core                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Policy Parser│  │Infra Monitor │  │Agent Memory  │          │
│  │   (Doctra)   │  │(DNS/IP/Cert) │  │   (Vector)   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
├─────────────────────────────────────────────────────────────────┤
│                     Violation Detection                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │SOAR Automation│ │Alert Manager │  │Report Gen    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

## Example Policies

The system includes sample SOC2 and ISO 27001 policies for demonstration:

### SOC2 Policy Requirements:
1. All external-facing systems must use TLS 1.2 or higher
2. Multi-factor authentication must be enabled for all administrative access
3. Security logs must be retained for at least 90 days
4. Vulnerability scans must be performed quarterly
5. All access must be on a need-to-know basis
6. Data encryption at rest is required for sensitive data

### Detection Rules:
- Certificate expiring within 7/30/60 days
- Missing SPF/DMARC records
- Malicious/suspicious IP addresses
- Tor exit nodes

## Configuration

Edit the agent initialization in `src/cli.ts` to customize:

```typescript
const agent = new ComplianceAgent('your-org-id', 'Your Organization');
```

## Enterprise Integration

The system supports integration with:
- **Slack**: Real-time alerts
- **JIRA**: Incident ticketing
- **PagerDuty**: On-call escalation
- **Email**: Notifications
- **Webhooks**: Custom integrations

## License

MIT
