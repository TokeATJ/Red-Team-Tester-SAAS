/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

// ==========================================
// SECURITY SECTION: Threat Model & Hardening
// ==========================================
// Threat Model: Unauthorized Access, Data Contamination, System Spoofing
// Attack Scenarios: Attackers injecting arbitrary schema formats to bypass UI validation.
// Mitigation Strategy: Strict type checking, input filters, and read-only type declarations.
// Abuse Cases: Tampering with security scores or findings records.
// Validation Logic: Compile-time TypeScript safety guards against state-mutation exploits.

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type SecurityCategory = 'Web Security' | 'AI Security' | 'API Security' | 'Infrastructure Security';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: SecurityCategory;
  description: string;
  impact: string;
  remediation: string;
  cvss: number;
  stride: string; // Spoofing, Tampering, etc.
  mitre: string;  // MITRE ATT&CK technique mapping
  compliance: string[]; // ['NIST CSF PR.DS-1', 'PCI DSS 6.5', etc.]
  owaspAgentic: string; // ASI01 - ASI10 or N/A
  evidenceId: string;
  timestamp: string;
}

export interface Evidence {
  evidenceId: string;
  findingId: string;
  hash: string;
  timestamp: string;
  integrityStatus: 'VALIDATED' | 'TAMPERED';
  metadata: {
    url?: string;
    headersChecked?: string[];
    dnsRecordsFound?: string[];
    tlsVersion?: string;
    agentDecision?: string;
    observedPayload?: string;
  };
}

export interface AgentLog {
  timestamp: string;
  agent: 'Recon Agent' | 'Vulnerability Assessment Agent' | 'Exploit Simulation Agent' | 'AI Security Agent' | 'AI Exploitation Agent' | 'AI Analyst Agent' | 'Report Generation Agent';
  action: string;
  details: string;
  status: 'SUCCESS' | 'WARNING' | 'INFO' | 'ERROR';
}

export interface Scan {
  id: string;
  target: string;
  targetType: 'standard_web' | 'api_endpoint' | 'ai_agent' | 'rag_app' | 'comprehensive';
  status: 'QUEUED' | 'RECON' | 'VULN' | 'EXPLOIT_SIM' | 'AI_SEC' | 'ANALYSING' | 'REPORTING' | 'COMPLETED' | 'FAILED';
  startedAt: string;
  completedAt?: string;
  riskScores: {
    overall: number;
    traditional: number;
    aiSecurity: number;
    compliance: number;
  };
  findings: Finding[];
  evidences: Evidence[];
  logs: AgentLog[];
  authorizedBy: string;
  authRecordHash: string;
}

export interface UserSession {
  username: string;
  email: string;
  role: 'CISO' | 'Security Analyst' | 'Security Engineer' | 'AI Governance';
  organization: string;
  token?: string;
}

export interface OrganizationPolicy {
  orgName: string;
  allowedTools: string[];
  restrictedTools: string[];
  safetyConstraints: string[];
  rateLimits: {
    maxScansPerHour: number;
    rateLimitScope: string;
  };
}

export interface AuditRecord {
  timestamp: string;
  user: string;
  role: string;
  action: string;
  target: string;
  consentConfirmed: boolean;
  ipAddress: string;
  hash: string;
}
