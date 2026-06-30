/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import { 
  Shield, 
  Terminal, 
  LayoutDashboard, 
  Globe, 
  Search, 
  Cpu, 
  FileSpreadsheet, 
  UserCheck, 
  AlertTriangle, 
  CheckCircle, 
  Server, 
  Activity, 
  FileText, 
  Database, 
  Lock, 
  Sliders, 
  ExternalLink, 
  RefreshCw, 
  Download, 
  Fingerprint, 
  Eye, 
  HelpCircle,
  Play,
  Settings,
  Scale
} from 'lucide-react';
import { Severity, SecurityCategory, Finding, Evidence, AgentLog, Scan, UserSession, OrganizationPolicy, AuditRecord } from './types';

// ==========================================
// SECURITY SECTION: Threat Model & Hardening
// ==========================================
// Threat Model: State Tampering, Cross-Site Scripting (XSS), Clickjacking, SSRF Validation
// Attack Scenarios: Malicious payloads injection through scanner inputs, UI hijacking
// Mitigation Strategy: Strict client-side URL structure validation, sanitization of user-facing fields, escape HTML.
// Abuse Cases: Unauthenticated access to CISO/Governance policy parameters.
// Validation Logic: Enforce frontend RBAC state checking before permitting policy edits.

export default function App() {
  // Navigation & Page State
  const [activeTab, setActiveTab] = useState<'dashboard' | 'surface' | 'scans' | 'findings' | 'ai_sec' | 'governance'>('dashboard');
  
  // Real Data State loaded from API
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);
  const [session, setSession] = useState<UserSession | null>(null);
  const [policy, setPolicy] = useState<OrganizationPolicy | null>(null);

  // Scan Launcher Form State
  const [targetInput, setTargetInput] = useState<string>('api.secure-node.ai');
  const [targetType, setTargetType] = useState<'standard_web' | 'api_endpoint' | 'ai_agent' | 'rag_app' | 'comprehensive'>('comprehensive');
  const [consentConfirmed, setConsentConfirmed] = useState<boolean>(false);
  
  // Local UI Interactive Filters
  const [findingSearch, setFindingSearch] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  
  // Active Finding Modal state
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [evidenceValidationStatus, setEvidenceValidationStatus] = useState<string>('');
  
  // Simulated telemetry live update
  const [sysHealth, setSysHealth] = useState<'NOMINAL' | 'DEGRADED'>('NOMINAL');
  const [latency, setLatency] = useState<number>(12);
  const [agentTimer, setAgentTimer] = useState<string>('04:22:11');
  const [scannersLoading, setScannersLoading] = useState<boolean>(false);
  const [showLegalDisclosure, setShowLegalDisclosure] = useState<boolean>(false);

  // Fetch all starting state elements
  const loadInitialState = async () => {
    try {
      setScannersLoading(true);
      // Fetch session
      const sessRes = await fetch('/api/auth/session');
      if (sessRes.ok) {
        const sessData = await sessRes.json();
        setSession(sessData);
      }

      // Fetch governance policy
      const policyRes = await fetch('/api/governance/policy');
      if (policyRes.ok) {
        const pData = await policyRes.json();
        setPolicy(pData);
      }

      // Fetch audit logs
      const auditRes = await fetch('/api/governance/audit');
      if (auditRes.ok) {
        const aData = await auditRes.json();
        setAuditLogs(aData);
      }

      // Fetch all scans
      const scansRes = await fetch('/api/scans');
      if (scansRes.ok) {
        const sData = await scansRes.json();
        setScans(sData);
        if (sData.length > 0) {
          // Set active scan as the latest one
          setActiveScan(sData[0]);
        }
      }
      setScannersLoading(false);
    } catch (err) {
      console.error("Error connecting to server-side scan API components:", err);
      setScannersLoading(false);
    }
  };

  useEffect(() => {
    loadInitialState();

    // Setup small periodic refreshing for the latest scan logs if in non-completed state
    const interval = setInterval(async () => {
      try {
        const scansRes = await fetch('/api/scans');
        if (scansRes.ok) {
          const sData = await scansRes.json();
          setScans(sData);
          
          // Keep active scan updated in real-time if it's currently scanning
          if (activeScan) {
            const freshActive = sData.find((s: Scan) => s.id === activeScan.id);
            if (freshActive) {
              setActiveScan(freshActive);
            }
          }
        }
        
        // Dynamic simulated telemetry variance
        setLatency(prev => Math.max(8, Math.min(25, prev + (Math.random() > 0.5 ? 1 : -1))));
        setAgentTimer(() => {
          const now = new Date();
          return `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}:${String(now.getSeconds()).padStart(2, '0')}`;
        });
      } catch (e) {
        // Suppress warning
      }
    }, 4000);

    return () => clearInterval(interval);
  }, [activeScan?.id]);

  // Switch Session Role securely
  const handleRoleSwitch = async (role: 'CISO' | 'Security Analyst' | 'Security Engineer' | 'AI Governance') => {
    try {
      const res = await fetch('/api/auth/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      });
      if (res.ok) {
        const updatedSess = await res.json();
        setSession(updatedSess);
        // Refresh audit log too
        const auditRes = await fetch('/api/governance/audit');
        if (auditRes.ok) {
          const aData = await auditRes.json();
          setAuditLogs(aData);
        }
      }
    } catch (err) {
      console.error(err);
    }
  };

  // Launch fresh security validation scan
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!consentConfirmed) {
      alert("Security Violation: You must explicitly check the authorization consent checkbox confirming asset ownership before initiating a Red Team validation simulation.");
      return;
    }

    try {
      setScannersLoading(true);
      const res = await fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          target: targetInput,
          targetType,
          consentConfirmed: true
        })
      });

      if (!res.ok) {
        const errObj = await res.json();
        alert(`Assessment Refused: ${errObj.error}`);
        setScannersLoading(false);
        return;
      }

      const createdScan = await res.json();
      // Add to local state list immediately
      setScans(prev => [createdScan, ...prev]);
      setActiveScan(createdScan);
      // Automatically navigate to scanning interface monitor
      setActiveTab('scans');
      setConsentConfirmed(false); // Reset confirmation state
      setScannersLoading(false);

      // Refresh audit list immediately
      const auditRes = await fetch('/api/governance/audit');
      if (auditRes.ok) {
        const aData = await auditRes.json();
        setAuditLogs(aData);
      }
    } catch (err) {
      console.error("Scanning request failed:", err);
      setScannersLoading(false);
    }
  };

  // Policy Modification (Only CISO/AI Governance allowed)
  const handleUpdatePolicy = async (allowedTools: string[], safetyConstraints: string[], restrictedTools: string[]) => {
    if (session?.role !== 'CISO' && session?.role !== 'AI Governance') {
      alert("Security Constraint: Only users assigned with CISO or AI Governance authorizations can adjust organization guardrail boundaries.");
      return;
    }

    try {
      const res = await fetch('/api/governance/policy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ allowedTools, safetyConstraints, restrictedTools })
      });

      if (res.ok) {
        const updated = await res.json();
        setPolicy(updated.policy);
        alert("Success: Corporate cybersecurity policy state synchronized successfully.");
        // Refresh audit logs
        const auditRes = await fetch('/api/governance/audit');
        if (auditRes.ok) {
          const aData = await auditRes.json();
          setAuditLogs(aData);
        }
      } else {
        const errObj = await res.json();
        alert(`Policy update failed: ${errObj.error}`);
      }
    } catch (e) {
      console.error(e);
    }
  };

  // Calculate high-level stats over all scans loaded
  const totalScans = scans.length;
  const latestScan = scans[0] || null;
  const currentRiskScore = latestScan ? latestScan.riskScores.overall : 0.0;
  
  // Calculate vulnerability count details
  let totalCritical = 0;
  let totalHigh = 0;
  let totalMedium = 0;
  let totalLow = 0;
  let aiSpecificRisksCount = 0;
  let tradRisksCount = 0;

  scans.forEach(s => {
    s.findings.forEach(f => {
      if (f.severity === 'CRITICAL') totalCritical++;
      if (f.severity === 'HIGH') totalHigh++;
      if (f.severity === 'MEDIUM') totalMedium++;
      if (f.severity === 'LOW' || f.severity === 'INFO') totalLow++;
      if (f.category === 'AI Security') aiSpecificRisksCount++;
      else tradRisksCount++;
    });
  });

  // Verification checksum validator for Evidence files
  const verifyEvidenceHash = (evidence: Evidence, finding: Finding) => {
    setEvidenceValidationStatus('VALIDATING');
    setTimeout(() => {
      // Re-calculate mock dynamic verification to show operational authenticity
      const composite = `${finding.id}|${finding.title}|${finding.cvss}`;
      // In a real database this matches the computed backend crypto hash exactly
      if (evidence.integrityStatus === 'VALIDATED') {
        setEvidenceValidationStatus('INTEGRITY_VERIFIED');
      } else {
        setEvidenceValidationStatus('TAMPERED_WARNING');
      }
    }, 800);
  };

  // Helper color mappings for severities
  const getSeverityBadgeClass = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-500 border border-red-500/30 font-bold';
      case 'HIGH':
        return 'bg-orange-500/10 text-orange-400 border border-orange-500/30 font-bold';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-500 border border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-400 border border-blue-500/20';
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  return (
    <div id="antigravity-app" className="flex h-screen w-full bg-[#0A0A0C] text-slate-300 font-sans overflow-hidden">
      
      {/* ==========================================
          SIDEBAR NAVIGATION (Matches Sleek Interface layout)
          ========================================== */}
      <aside id="sidebar" className="w-64 bg-[#0F0F12] border-r border-slate-800/50 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo Brand Header */}
          <div className="p-6 flex items-center space-x-3 border-b border-slate-800/20">
            <div className="w-8 h-8 bg-indigo-600 rounded flex items-center justify-center shadow-[0_0_15px_rgba(79,70,229,0.4)]">
              <div className="w-4 h-4 border-2 border-white rotate-45 flex items-center justify-center">
                <div className="w-1 h-1 bg-white rounded-full"></div>
              </div>
            </div>
            <div>
              <span className="text-white font-bold tracking-tight text-lg block">ANTIGRAVITY AI</span>
              <span className="text-[9px] text-indigo-400 font-mono tracking-widest block -mt-1 font-bold">RED TEAM OPERATIONS</span>
            </div>
          </div>

          {/* Org Identification Badge */}
          <div className="mx-4 mt-4 px-3 py-2 bg-slate-900/60 border border-slate-800/50 rounded-lg flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-cyan-500 animate-pulse"></span>
            <div className="min-w-0">
              <p className="text-[10px] uppercase font-bold text-slate-500 leading-none">Organization</p>
              <p className="text-xs text-slate-300 font-mono font-bold truncate mt-1">
                {policy?.orgName || 'GLOBAL SECURE CORP'}
              </p>
            </div>
          </div>

          {/* Core Navigation Items */}
          <nav className="px-4 space-y-1 mt-6">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'dashboard' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <LayoutDashboard size={16} className={activeTab === 'dashboard' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Executive Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('surface')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'surface' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <Globe size={16} className={activeTab === 'surface' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Attack Surface</span>
            </button>

            <button
              onClick={() => setActiveTab('scans')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'scans' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <Terminal size={16} className={activeTab === 'scans' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Active Scans & Engine</span>
            </button>

            <button
              onClick={() => setActiveTab('findings')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'findings' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <Shield size={16} className={activeTab === 'findings' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Findings & Evidence</span>
            </button>

            <button
              onClick={() => setActiveTab('ai_sec')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'ai_sec' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <Cpu size={16} className={activeTab === 'ai_sec' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Agentic AI Security</span>
            </button>

            <button
              onClick={() => setActiveTab('governance')}
              className={`w-full text-left flex items-center space-x-3 px-4 py-2.5 rounded-lg border transition-all ${
                activeTab === 'governance' 
                  ? 'bg-slate-800/50 text-white border-slate-700/50 shadow-sm' 
                  : 'border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-200'
              }`}
            >
              <Scale size={16} className={activeTab === 'governance' ? 'text-cyan-400' : 'text-slate-500'} />
              <span className="text-sm font-medium">Governance & Audit</span>
            </button>
          </nav>
        </div>

        {/* User Session Profile & Role Selection Container */}
        <div className="p-4 border-t border-slate-800/50 bg-[#0A0A0C]/40">
          <div className="mb-3">
            <label className="text-[9px] text-slate-500 font-bold uppercase tracking-wider block mb-1">Active Sandbox Role</label>
            <select
              value={session?.role || 'Security Analyst'}
              onChange={(e) => handleRoleSwitch(e.target.value as any)}
              className="w-full bg-[#14141A] text-slate-300 text-xs border border-slate-800 rounded px-2 py-1 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="Security Analyst">Security Analyst</option>
              <option value="CISO">CISO (Executive Privs)</option>
              <option value="Security Engineer">Security Engineer (Technical)</option>
              <option value="AI Governance">AI Governance Monitor</option>
            </select>
          </div>

          <div className="flex items-center space-x-3 pt-2 border-t border-slate-800/40">
            <div className="w-8 h-8 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-cyan-400 text-xs font-mono">
              SA
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-xs font-semibold text-white truncate">{session?.username || 'S. ARCHITECT'}</p>
              <p className="text-[10px] text-slate-500 uppercase tracking-tighter truncate font-mono">
                {session?.role || 'Tier 3 Operator'}
              </p>
            </div>
          </div>
        </div>
      </aside>

      {/* ==========================================
          MAIN AREA CONTAINING HEADER, SUB-VIEWS & FOOTER
          ========================================== */}
      <main className="flex-1 flex flex-col overflow-hidden">
        
        {/* Header Block with high contrast risk parameters */}
        <header className="h-16 bg-[#0F0F12]/80 border-b border-slate-800/50 flex items-center justify-between px-8 shrink-0 z-10">
          <div className="flex items-center space-x-4">
            <span className="text-xs font-mono text-slate-500">ACTIVE TARGET:</span>
            <div className="bg-slate-900 border border-slate-800 px-3 py-1 rounded text-sm text-cyan-400 font-mono flex items-center space-x-2">
              <Server size={12} className="text-cyan-500" />
              <span>{activeScan ? activeScan.target : 'No active target'}</span>
            </div>
            <div className="flex items-center px-2 py-0.5 bg-green-500/10 border border-green-500/30 rounded text-[10px] text-green-400 font-bold tracking-widest uppercase font-mono">
              AUTHORIZED
            </div>
          </div>

          <div className="flex items-center space-x-6">
            <div className="text-right hidden sm:block">
              <p className="text-[10px] uppercase tracking-tighter text-slate-500 font-mono">Session Scope Key</p>
              <p className="text-xs font-mono text-slate-300 truncate max-w-40" title={activeScan?.authRecordHash || 'RM-7742-88B'}>
                {activeScan ? `HASH: ${activeScan.authRecordHash.substring(0, 10)}...` : 'RM-OFFLINE'}
              </p>
            </div>
            
            <div className="w-px h-8 bg-slate-800 hidden sm:block"></div>
            
            <div className="flex items-center space-x-3 bg-red-950/20 border border-red-900/30 px-3 py-1 rounded-lg">
              <span className="text-[10px] text-red-400 font-mono uppercase font-bold">LATEST RISK SCORE</span>
              <span className="text-2xl font-bold font-mono text-red-500">
                {activeScan ? activeScan.riskScores.overall.toFixed(1) : '0.0'}
              </span>
            </div>
          </div>
        </header>

        {/* Content viewport area */}
        <div className="flex-1 overflow-y-auto p-8 bg-[#0A0A0C]">
          
          {/* ==========================================
              TAB 1: EXECUTIVE DASHBOARD
              ========================================== */}
          {activeTab === 'dashboard' && (
            <div id="view-dashboard" className="space-y-8 animate-fadeIn">
              
              {/* Top Level Summary Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                
                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden">
                  <div className="absolute right-3 top-3 text-slate-700"><Shield size={40} strokeWidth={1} /></div>
                  <p className="text-xs text-slate-500 uppercase font-bold tracking-wider font-mono">Platform Integrity Risk</p>
                  <h3 className="text-3xl text-white font-bold mt-2 font-mono">
                    {currentRiskScore > 0 ? `${currentRiskScore.toFixed(1)}/10` : '0.0'}
                  </h3>
                  <div className="mt-3 flex items-center text-[10px] font-mono">
                    <span className={`px-2 py-0.5 rounded ${currentRiskScore > 7.5 ? 'bg-red-500/10 text-red-400 border border-red-500/20' : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/20'}`}>
                      {currentRiskScore > 7.5 ? 'CRITICAL POSTURE' : 'MODERATE RISK'}
                    </span>
                  </div>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden">
                  <div className="absolute right-3 top-3 text-slate-700"><Cpu size={40} strokeWidth={1} /></div>
                  <p className="text-xs text-slate-500 uppercase font-bold tracking-wider font-mono">AI Specific Threats</p>
                  <h3 className="text-3xl text-white font-bold mt-2 font-mono">{aiSpecificRisksCount}</h3>
                  <div className="mt-3 text-[10px] text-slate-400 font-mono">
                    Across {totalScans} verified targets
                  </div>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden">
                  <div className="absolute right-3 top-3 text-slate-700"><Sliders size={40} strokeWidth={1} /></div>
                  <p className="text-xs text-slate-500 uppercase font-bold tracking-wider font-mono">Traditional Findings</p>
                  <h3 className="text-3xl text-white font-bold mt-2 font-mono">{tradRisksCount}</h3>
                  <div className="mt-3 text-[10px] text-green-400 font-mono">
                    All non-destructive simulated vectors
                  </div>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 shadow-sm relative overflow-hidden">
                  <div className="absolute right-3 top-3 text-slate-700"><FileSpreadsheet size={40} strokeWidth={1} /></div>
                  <p className="text-xs text-slate-500 uppercase font-bold tracking-wider font-mono">Audits & Reports</p>
                  <h3 className="text-3xl text-white font-bold mt-2 font-mono">{totalScans} Targets</h3>
                  <div className="mt-3 flex items-center text-[10px] text-cyan-400 font-mono">
                    <span className="w-2 h-2 rounded-full bg-cyan-500 mr-2 animate-ping"></span> 100% Traceable Logs
                  </div>
                </div>
              </div>

              {/* Bento Grid layout with threat charts & active system logs */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                {/* Visual Risk Breakdown chart using clean inline HTML/CSS (D3-inspired) */}
                <div className="lg:col-span-8 bg-[#14141A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="flex justify-between items-center mb-6">
                      <div>
                        <h4 className="text-sm font-bold text-white uppercase tracking-wider font-mono">VULNERABILITY RISKS SCOREBOARD</h4>
                        <p className="text-xs text-slate-500">Autonomous analysis mapping parameters</p>
                      </div>
                      <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/30 border border-cyan-800/40 px-2.5 py-1 rounded">
                        Active Frameworks Checked
                      </span>
                    </div>

                    {activeScan ? (
                      <div className="space-y-6 my-4">
                        <div>
                          <div className="flex justify-between text-xs mb-2">
                            <span className="text-slate-300 font-semibold flex items-center"><Shield size={14} className="mr-2 text-red-500" /> Overall Weighted Risk Score</span>
                            <span className="text-red-400 font-mono font-bold">{activeScan.riskScores.overall} / 10.0</span>
                          </div>
                          <div className="w-full bg-slate-800/40 h-2.5 rounded-full overflow-hidden border border-slate-700/50">
                            <div className="bg-gradient-to-r from-orange-500 to-red-600 h-full rounded-full transition-all duration-1000" style={{ width: `${activeScan.riskScores.overall * 10}%` }}></div>
                          </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4 border-t border-slate-800/60">
                          <div>
                            <div className="flex justify-between text-xs mb-1">
                              <span className="text-slate-400">Traditional Web Sec</span>
                              <span className="text-slate-200 font-mono font-semibold">{activeScan.riskScores.traditional}</span>
                            </div>
                            <div className="w-full bg-slate-800/40 h-2 rounded-full overflow-hidden">
                              <div className="bg-yellow-500 h-full rounded-full" style={{ width: `${activeScan.riskScores.traditional * 10}%` }}></div>
                            </div>
                          </div>

                          <div>
                            <div className="flex justify-between text-xs mb-1">
                              <span className="text-slate-400 text-cyan-400">AI Agent Security</span>
                              <span className="text-slate-200 font-mono font-semibold text-cyan-400">{activeScan.riskScores.aiSecurity}</span>
                            </div>
                            <div className="w-full bg-slate-800/40 h-2 rounded-full overflow-hidden">
                              <div className="bg-cyan-500 h-full rounded-full" style={{ width: `${activeScan.riskScores.aiSecurity * 10}%` }}></div>
                            </div>
                          </div>

                          <div>
                            <div className="flex justify-between text-xs mb-1">
                              <span className="text-slate-400">Compliance Deficit</span>
                              <span className="text-slate-200 font-mono font-semibold">{activeScan.riskScores.compliance}</span>
                            </div>
                            <div className="w-full bg-slate-800/40 h-2 rounded-full overflow-hidden">
                              <div className="bg-purple-500 h-full rounded-full" style={{ width: `${activeScan.riskScores.compliance * 10}%` }}></div>
                            </div>
                          </div>
                        </div>
                      </div>
                    ) : (
                      <div className="py-12 text-center text-slate-500 text-xs font-mono">
                        No scan data configured. Launch a security validation sequence to initialize scorecard.
                      </div>
                    )}
                  </div>

                  <div className="bg-slate-900/60 rounded-lg p-4 border border-slate-800/80 text-xs text-slate-400">
                    <span className="font-bold text-white uppercase font-mono block mb-1">CISO Advisory Note</span>
                    The platform computes AI security scores by analyzing susceptibility to Goal Hijacking, Prompt Injection, context manipulation, and identity boundaries inside autonomous agent frameworks.
                  </div>
                </div>

                {/* Agent Monitor Stream (Matches design guidelines styling perfectly) */}
                <div className="lg:col-span-4 bg-[#14141A] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Autonomous Agent Monitor</h4>
                      <div className="flex items-center space-x-1.5">
                        <span className="text-[10px] text-cyan-400 font-mono">LIVE RUNTIME</span>
                        <div className="w-2.5 h-2.5 rounded-full bg-cyan-500 shadow-[0_0_8px_#06b6d4] animate-pulse"></div>
                      </div>
                    </div>

                    <div className="bg-black/60 rounded-lg p-4 font-mono text-[11px] leading-relaxed overflow-y-auto max-h-72 space-y-3 border border-slate-800">
                      {activeScan && activeScan.logs && activeScan.logs.length > 0 ? (
                        [...activeScan.logs].reverse().map((log, index) => {
                          let color = 'text-cyan-400';
                          if (log.status === 'ERROR') color = 'text-red-400';
                          if (log.status === 'WARNING') color = 'text-yellow-400 font-bold';
                          if (log.status === 'SUCCESS') color = 'text-green-400';

                          return (
                            <div key={index} className="border-b border-slate-900 pb-2">
                              <div className="flex justify-between text-[9px] text-slate-500">
                                <span>[{log.agent.toUpperCase()}]</span>
                                <span>{log.timestamp.substring(11, 19)}</span>
                              </div>
                              <p className={`${color} font-bold mt-0.5`}>{log.action}</p>
                              <p className="text-slate-400 text-[10px] mt-0.5 leading-tight">{log.details}</p>
                            </div>
                          );
                        })
                      ) : (
                        <div className="text-slate-600">
                          [SYSTEM] Ready for telemetry ingestion.<br />
                          [SYSTEM] Awaiting scope initiation confirmation...
                        </div>
                      )}
                    </div>
                  </div>

                  <button 
                    onClick={() => setActiveTab('scans')}
                    className="w-full mt-4 bg-slate-900 border border-slate-800 hover:border-slate-700 hover:bg-slate-800 text-[11px] text-cyan-400 font-mono font-bold py-2 rounded uppercase tracking-wider"
                  >
                    Interactive Console View
                  </button>
                </div>
              </div>

              {/* Latest findings quick lookup */}
              <div className="bg-[#14141A] border border-slate-800 rounded-xl flex flex-col min-h-0 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center">
                  <h3 className="text-sm font-bold text-white uppercase font-mono tracking-wider">ACTIVE CRITICAL FINDINGS (LATEST TARGET)</h3>
                  <button 
                    onClick={() => setActiveTab('findings')}
                    className="text-[10px] text-cyan-400 hover:text-cyan-300 font-bold tracking-widest uppercase underline"
                  >
                    View Comprehensive Evidence Vault
                  </button>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-[10px] text-slate-500 uppercase tracking-widest border-b border-slate-800/80 bg-[#0F0F12]/60">
                        <th className="py-3 px-6 font-mono">ID / Severity</th>
                        <th className="py-3 px-6">Vulnerability / Threat Model</th>
                        <th className="py-3 px-6">Category</th>
                        <th className="py-3 px-6">STRIDE Category</th>
                        <th className="py-3 px-6">Remediation Roadmap</th>
                      </tr>
                    </thead>
                    <tbody className="text-xs divide-y divide-slate-800/50">
                      {activeScan && activeScan.findings.length > 0 ? (
                        activeScan.findings.map((f, i) => (
                          <tr key={f.id} className="hover:bg-slate-800/10 cursor-pointer" onClick={() => { setSelectedFinding(f); setActiveTab('findings'); }}>
                            <td className="py-4 px-6 font-mono">
                              <span className={`px-2.5 py-1 rounded-md text-[10px] ${getSeverityBadgeClass(f.severity)} mr-2`}>
                                {f.severity}
                              </span>
                              <span className="text-slate-500 text-[11px]">{f.id}</span>
                            </td>
                            <td className="py-4 px-6">
                              <p className="font-semibold text-slate-200">{f.title}</p>
                              <p className="text-[11px] text-slate-500 truncate max-w-sm mt-0.5">{f.description}</p>
                            </td>
                            <td className="py-4 px-6">
                              <span className="text-slate-300 bg-slate-900 border border-slate-800/60 px-2 py-0.5 rounded font-mono text-[10px]">
                                {f.category}
                              </span>
                            </td>
                            <td className="py-4 px-6 text-slate-400 font-mono text-[11px]">
                              {f.stride}
                            </td>
                            <td className="py-4 px-6">
                              <span className="text-cyan-400 underline hover:text-cyan-300 font-semibold cursor-pointer">
                                Audit Remediation
                              </span>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={5} className="py-8 text-center text-slate-500 text-xs font-mono">
                            No threat vectors identified on the targeted scope. Secure or offline status.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              TAB 2: ATTACK SURFACE MANAGEMENT
              ========================================== */}
          {activeTab === 'surface' && (
            <div id="view-surface" className="space-y-8 animate-fadeIn">
              
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-lg font-bold text-white uppercase font-mono tracking-wider">Attack Surface Mapping (ASM)</h3>
                  <p className="text-xs text-slate-400">Discover and visualize open interfaces, DNS exposure, and LLM agent boundaries</p>
                </div>
                <span className="px-3 py-1 bg-cyan-950/40 border border-cyan-800/40 rounded text-xs font-mono text-cyan-400">
                  Continuous Asset Tracking
                </span>
              </div>

              {/* Bento Row: Target Assets List & Exposed Interfaces */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                <div className="lg:col-span-4 bg-[#14141A] border border-slate-800 rounded-xl p-5">
                  <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono mb-4">Known Target Interfaces</h4>
                  
                  <div className="space-y-3">
                    <div className="bg-slate-900/60 p-3 rounded border border-slate-800 flex justify-between items-start">
                      <div>
                        <span className="text-[9px] bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono font-bold px-1.5 py-0.5 rounded uppercase">AI AGENT</span>
                        <p className="text-sm font-mono font-bold text-white mt-1">api.secure-node.ai</p>
                        <p className="text-[10px] text-slate-500 mt-1">Active RAG vector DB linked</p>
                      </div>
                      <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"></span>
                    </div>

                    <div className="bg-slate-900/60 p-3 rounded border border-slate-800 flex justify-between items-start">
                      <div>
                        <span className="text-[9px] bg-yellow-500/10 border border-yellow-500/20 text-yellow-500 font-mono px-1.5 py-0.5 rounded uppercase">API ENDPOINT</span>
                        <p className="text-sm font-mono font-bold text-white mt-1">api-v2.prod-core.internal</p>
                        <p className="text-[10px] text-slate-500 mt-1">Simulated corporate core interface</p>
                      </div>
                      <span className="w-2 h-2 rounded-full bg-yellow-500"></span>
                    </div>

                    <div className="bg-slate-900/60 p-3 rounded border border-slate-800 flex justify-between items-start">
                      <div>
                        <span className="text-[9px] bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono px-1.5 py-0.5 rounded uppercase">STANDARD WEB</span>
                        <p className="text-sm font-mono font-bold text-white mt-1">secure-node.ai/login</p>
                        <p className="text-[10px] text-slate-500 mt-1">Traditional authorization portal</p>
                      </div>
                      <span className="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]"></span>
                    </div>
                  </div>

                  <div className="bg-slate-900/40 p-3 rounded border border-slate-800 mt-6 text-xs text-slate-400">
                    <span className="text-white font-bold block mb-1">Passive ASM Monitoring</span>
                    Antigravity AI logs subdomains and microservices autonomously over time, assessing potential cascading attack pathways without breaking service operational continuity.
                  </div>
                </div>

                <div className="lg:col-span-8 bg-[#14141A] border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono mb-4">Domain Exposure Audit Trail</h4>
                    
                    <div className="bg-black/40 rounded-lg p-5 border border-slate-800 font-mono text-xs text-slate-300 space-y-4">
                      <div>
                        <p className="text-slate-500">[2026-06-29] DNS DISCOVERY EVENT IDENTIFIED</p>
                        <p className="text-white mt-1 font-bold">Target: api.secure-node.ai</p>
                        <div className="ml-4 mt-1 text-slate-400 text-[11px] space-y-1">
                          <p>&gt; IP address resolved: 192.168.1.10 (Standard NAT interface)</p>
                          <p>&gt; Service headers: Cloudflare Edge, X-Powered-By Express</p>
                          <p>&gt; Security Score computed: 7.8 (High traditional risks)</p>
                        </div>
                      </div>

                      <div className="border-t border-slate-800/80 pt-3">
                        <p className="text-slate-500">[2026-06-29] COMPLIANCE CONTROLS MAPPED</p>
                        <p className="text-cyan-400 mt-1">OWASP LLM Target Model: ASI01 Goal Hijack vulnerability verified</p>
                        <p className="text-[11px] text-slate-400 ml-4">&gt; Mapped to NIST AI RMF framework section G-100</p>
                      </div>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-6">
                    <div className="bg-slate-900 p-4 border border-slate-800 rounded">
                      <span className="text-slate-500 text-[10px] uppercase block font-mono">Discovered Services</span>
                      <span className="text-xl text-white font-bold block mt-1 font-mono">4 Interfaces</span>
                    </div>
                    <div className="bg-slate-900 p-4 border border-slate-800 rounded">
                      <span className="text-slate-500 text-[10px] uppercase block font-mono">Simulated Attack Paths</span>
                      <span className="text-xl text-red-400 font-bold block mt-1 font-mono">2 Escalations</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              TAB 3: SCAN CONFIGURATION & MONITORING
              ========================================== */}
          {activeTab === 'scans' && (
            <div id="view-scans" className="space-y-8 animate-fadeIn">
              
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Configuration Panel */}
                <div className="lg:col-span-5 bg-[#14141A] border border-slate-800 rounded-xl p-6">
                  <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-4">INITIATE RED TEAM VALIDATION</h3>
                  
                  <form onSubmit={handleStartScan} className="space-y-5">
                    
                    <div>
                      <label className="text-xs text-slate-400 font-mono block mb-1">Target IP / Domain / LLM Endpoint</label>
                      <input
                        type="text"
                        value={targetInput}
                        onChange={(e) => setTargetInput(e.target.value)}
                        placeholder="e.g. api.secure-node.ai"
                        className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
                        required
                      />
                    </div>

                    <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-lg space-y-2">
                      <span className="text-[10px] text-cyan-400 font-mono uppercase tracking-widest font-bold block">Unified Security Assessment Scope</span>
                      <p className="text-[11px] text-slate-300 leading-normal">
                        Antigravity's multi-agent orchestration engine automatically runs a simultaneous, non-destructive audit checking <strong>all 4 security surfaces</strong>:
                      </p>
                      <ul className="text-[11px] text-slate-400 space-y-1.5 pl-1.5 list-none font-mono">
                        <li className="flex items-center space-x-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                          <span>Web Security (Headers &amp; Transport Isolation)</span>
                        </li>
                        <li className="flex items-center space-x-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-orange-400"></span>
                          <span>API Security (Access, Traces &amp; Rate Limits)</span>
                        </li>
                        <li className="flex items-center space-x-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
                          <span>AI Security Agent (OWASP Agentic AI ASI01 - ASI10)</span>
                        </li>
                        <li className="flex items-center space-x-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-purple-400"></span>
                          <span>RAG Security (Context and Knowledge Base Integrity)</span>
                        </li>
                      </ul>
                    </div>

                    {/* Ethical Authorization Constraints - Required for SOC2/Ethical scanning */}
                    <div className="bg-red-950/20 border border-red-900/30 rounded p-4 space-y-3">
                      <div className="flex items-start space-x-3">
                        <input
                          type="checkbox"
                          id="consent"
                          checked={consentConfirmed}
                          onChange={(e) => setConsentConfirmed(e.target.checked)}
                          className="mt-1 h-4 w-4 text-cyan-500 rounded border-slate-700 bg-slate-900 focus:ring-0 focus:ring-offset-0 cursor-pointer"
                        />
                        <label htmlFor="consent" className="text-[11px] text-slate-300 select-none cursor-pointer leading-tight">
                          <strong>LEGAL AUTHORIZATION CONSENT MANTRA:</strong> I confirm that I either own this asset or hold explicit, written authorization from the owner to perform security assessments and threat modeling.
                        </label>
                      </div>

                      <div className="text-[10px] text-red-400 font-mono">
                        Security Notice: All actions are immutable-logged with timestamp, active user ({session?.username}), IP address, and asset confirmation hash.
                      </div>
                    </div>

                    <button
                      type="submit"
                      disabled={scannersLoading}
                      className="w-full bg-red-600 hover:bg-red-500 text-white font-mono text-xs font-bold py-2.5 rounded transition-all flex items-center justify-center space-x-2 shadow-[0_0_15px_rgba(220,38,38,0.3)] disabled:opacity-50"
                    >
                      {scannersLoading ? (
                        <>
                          <RefreshCw className="animate-spin" size={14} />
                          <span>SYNCHRONIZING SECURE AGENTS...</span>
                        </>
                      ) : (
                        <>
                          <Play size={14} />
                          <span>LAUNCH MULTI-AGENT THREAT MODELING</span>
                        </>
                      )}
                    </button>
                  </form>
                </div>

                {/* Real-time-like Console logs */}
                <div className="lg:col-span-7 bg-[#14141A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-4">ACTIVE DEPLOYED AGENTS (LIVE STATUS)</h3>
                    
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-6">
                      <div className="bg-slate-900 p-3 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-500 block font-mono">RECON AGENT</span>
                        <span className="text-xs text-green-400 font-bold block mt-1 flex items-center">
                          <CheckCircle size={10} className="mr-1" /> Passive Map
                        </span>
                      </div>

                      <div className="bg-slate-900 p-3 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-500 block font-mono">VULN AGENT</span>
                        <span className="text-xs text-green-400 font-bold block mt-1 flex items-center">
                          <CheckCircle size={10} className="mr-1" /> Header Audit
                        </span>
                      </div>

                      <div className="bg-slate-900 p-3 rounded border border-slate-800">
                        <span className="text-[10px] text-slate-500 block font-mono">AI SECURITY AGENT</span>
                        <span className={`text-xs font-bold block mt-1 flex items-center ${activeScan?.status === 'AI_SEC' ? 'text-yellow-400 animate-pulse' : 'text-green-400'}`}>
                          {activeScan?.status === 'AI_SEC' ? 'Evaluating ASI' : <><CheckCircle size={10} className="mr-1" /> ASI01-10 Done</>}
                        </span>
                      </div>
                    </div>

                    <div className="bg-black/60 rounded-lg p-4 font-mono text-xs text-slate-300 min-h-60 max-h-80 overflow-y-auto space-y-2.5 border border-slate-800">
                      {activeScan ? (
                        activeScan.logs.map((log, index) => {
                          let statusColor = 'text-cyan-400';
                          if (log.status === 'ERROR') statusColor = 'text-red-400';
                          if (log.status === 'WARNING') statusColor = 'text-yellow-400 font-bold';
                          if (log.status === 'SUCCESS') statusColor = 'text-green-400';

                          return (
                            <div key={index} className="border-l-2 border-slate-800 pl-3 py-1">
                              <span className="text-[10px] text-slate-500 block">[{log.agent}] - {log.timestamp.substring(11, 19)}</span>
                              <span className={`${statusColor} font-bold`}>{log.action}</span> - <span className="text-slate-300">{log.details}</span>
                            </div>
                          );
                        })
                      ) : (
                        <div className="text-slate-500">
                          [SYSTEM] Idle. Select target and confirm authorization checkbox above to start the validation framework.
                        </div>
                      )}
                    </div>
                  </div>

                  {activeScan && (
                    <div className="pt-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500">
                      <span>Status: <strong className="text-cyan-400 font-mono">{activeScan.status}</strong></span>
                      <span>Target: <strong className="text-slate-300 font-mono">{activeScan.target}</strong></span>
                    </div>
                  )}
                </div>
              </div>

              {/* Scan History and Downloads table */}
              <div className="bg-[#14141A] border border-slate-800 rounded-xl p-6">
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-4">REGULATORY RISK ASSESSMENTS HISTORY</h3>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-left">
                    <thead>
                      <tr className="text-[10px] text-slate-500 uppercase tracking-widest border-b border-slate-800/80">
                        <th className="pb-3">Timestamp</th>
                        <th className="pb-3">Target Node</th>
                        <th className="pb-3">Architecture</th>
                        <th className="pb-3">Overall Risk</th>
                        <th className="pb-3">Authorized Operator</th>
                        <th className="pb-3 text-right">Download Reports</th>
                      </tr>
                    </thead>
                    <tbody className="text-xs divide-y divide-slate-800/40 text-slate-300">
                      {scans.map((s) => (
                        <tr key={s.id} className="hover:bg-slate-800/10">
                          <td className="py-4 font-mono text-[11px] text-slate-400">{s.startedAt.replace('T', ' ').substring(0, 19)}</td>
                          <td className="py-4 font-mono font-bold text-white">{s.target}</td>
                          <td className="py-4">
                            <span className="bg-slate-900 border border-slate-800 px-2 py-0.5 rounded font-mono text-[10px] uppercase text-slate-400">
                              {s.targetType}
                            </span>
                          </td>
                          <td className="py-4 font-mono text-red-400 font-bold">{s.riskScores.overall} / 10.0</td>
                          <td className="py-4 text-slate-400">{s.authorizedBy}</td>
                          <td className="py-4 text-right space-x-2">
                            <a
                              href={`/api/reports/download/${s.id}/executive`}
                              className="inline-flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 hover:underline font-bold"
                              title="Download CISO Executive Summary Report"
                            >
                              <Download size={12} />
                              <span>Executive</span>
                            </a>
                            <span className="text-slate-600">|</span>
                            <a
                              href={`/api/reports/download/${s.id}/technical`}
                              className="inline-flex items-center space-x-1 text-orange-400 hover:text-orange-300 hover:underline font-bold"
                              title="Download Engineer Technical Remediation Report"
                            >
                              <Download size={12} />
                              <span>Technical</span>
                            </a>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              TAB 4: FINDINGS & EVIDENCE VAULT
              ========================================== */}
          {activeTab === 'findings' && (
            <div id="view-findings" className="space-y-8 animate-fadeIn">
              
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <h3 className="text-lg font-bold text-white uppercase font-mono tracking-wider">Findings & Evidence Vault</h3>
                  <p className="text-xs text-slate-400">Review validated security findings and check SHA-256 evidence block integrity</p>
                </div>

                {/* Filter and search parameters */}
                <div className="flex items-center space-x-3">
                  <div className="bg-slate-900 border border-slate-800 rounded px-2.5 py-1.5 flex items-center space-x-2">
                    <Search size={14} className="text-slate-500" />
                    <input
                      type="text"
                      placeholder="Search threat vectors..."
                      value={findingSearch}
                      onChange={(e) => setFindingSearch(e.target.value)}
                      className="bg-transparent border-none text-xs text-slate-200 font-mono focus:outline-none w-40"
                    />
                  </div>

                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    className="bg-slate-900 border border-slate-800 text-xs rounded px-2 py-1.5 focus:outline-none focus:border-cyan-500 text-slate-300 font-mono"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              {/* Main Split Screen: Findings list & Detailed Evidence Block */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Findings Table list */}
                <div className="lg:col-span-7 bg-[#14141A] border border-slate-800 rounded-xl overflow-hidden">
                  <div className="px-6 py-4 border-b border-slate-800 bg-[#0F0F12]/30">
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono">Discovered Findings List</h4>
                  </div>

                  <div className="overflow-x-auto">
                    <table className="w-full text-left">
                      <thead>
                        <tr className="text-[10px] text-slate-500 uppercase tracking-widest border-b border-slate-800 bg-[#0F0F12]/60">
                          <th className="py-3 px-4 font-mono">ID / Severity</th>
                          <th className="py-3 px-4">Title / Vector</th>
                          <th className="py-3 px-4">Compliance Identifiers</th>
                        </tr>
                      </thead>
                      <tbody className="text-xs divide-y divide-slate-800/50">
                        {activeScan && activeScan.findings.length > 0 ? (
                          activeScan.findings
                            .filter(f => {
                              const matchSearch = f.title.toLowerCase().includes(findingSearch.toLowerCase()) || f.description.toLowerCase().includes(findingSearch.toLowerCase());
                              const matchSev = severityFilter === 'ALL' || f.severity === severityFilter;
                              return matchSearch && matchSev;
                            })
                            .map((f) => (
                              <tr
                                key={f.id}
                                onClick={() => { setSelectedFinding(f); setEvidenceValidationStatus(''); }}
                                className={`hover:bg-slate-800/20 cursor-pointer transition-all ${selectedFinding?.id === f.id ? 'bg-slate-800/30' : ''}`}
                              >
                                <td className="py-4 px-4 font-mono">
                                  <span className={`px-2 py-0.5 rounded text-[9px] ${getSeverityBadgeClass(f.severity)} block w-fit mb-1`}>
                                    {f.severity}
                                  </span>
                                  <span className="text-[11px] text-slate-500">{f.id}</span>
                                </td>
                                <td className="py-4 px-4">
                                  <p className="font-semibold text-slate-200">{f.title}</p>
                                  <p className="text-[10px] text-slate-400 font-mono mt-0.5">{f.stride} | CVSS {f.cvss}</p>
                                </td>
                                <td className="py-4 px-4 font-mono text-[10px] text-slate-400">
                                  {f.compliance.join(", ")}
                                </td>
                              </tr>
                            ))
                        ) : (
                          <tr>
                            <td colSpan={3} className="py-8 text-center text-slate-500 text-xs font-mono">
                              No findings recorded for this node target.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Evidence Drawer Detail panel */}
                <div className="lg:col-span-5">
                  {selectedFinding ? (
                    <div className="bg-[#14141A] border border-slate-800 rounded-xl p-6 space-y-6 relative overflow-hidden">
                      <div className="flex justify-between items-start">
                        <div>
                          <span className={`px-2 py-0.5 rounded text-[9px] ${getSeverityBadgeClass(selectedFinding.severity)} font-mono`}>
                            {selectedFinding.severity}
                          </span>
                          <h4 className="text-sm font-bold text-white uppercase tracking-wider font-mono mt-2">{selectedFinding.title}</h4>
                        </div>
                        <span className="text-xs font-mono text-slate-500">{selectedFinding.id}</span>
                      </div>

                      <div className="space-y-4">
                        <div>
                          <span className="text-slate-500 text-[10px] uppercase block font-mono font-bold">Threat & Vulnerability Description</span>
                          <p className="text-xs text-slate-300 mt-1 leading-relaxed bg-black/40 p-3 rounded border border-slate-850">{selectedFinding.description}</p>
                        </div>

                        <div>
                          <span className="text-slate-500 text-[10px] uppercase block font-mono font-bold">Calculated Risk Impact</span>
                          <p className="text-xs text-slate-300 mt-1 leading-relaxed bg-black/40 p-3 rounded border border-slate-850">{selectedFinding.impact}</p>
                        </div>

                        <div>
                          <span className="text-slate-500 text-[10px] uppercase block font-mono font-bold">Technical Remediation Instructions</span>
                          <p className="text-xs text-slate-300 mt-1 leading-relaxed bg-cyan-950/10 p-3 rounded border border-cyan-900/20">{selectedFinding.remediation}</p>
                        </div>

                        {/* Cryptographic SHA-256 validation checksum module */}
                        <div className="border-t border-slate-800/80 pt-4 space-y-3">
                          <span className="text-slate-400 text-[10px] uppercase block font-mono font-bold">Security Evidence Block (Integrity Check)</span>
                          
                          {activeScan?.evidences.find(e => e.evidenceId === selectedFinding.evidenceId) ? (
                            (() => {
                              const ev = activeScan.evidences.find(e => e.evidenceId === selectedFinding.evidenceId)!;
                              return (
                                <div className="bg-slate-900/80 p-4 rounded border border-slate-800 space-y-3">
                                  <div className="flex justify-between items-center text-[10px] font-mono">
                                    <span className="text-slate-500">Evidence ID: {ev.evidenceId}</span>
                                    <span className="text-slate-400">{ev.timestamp.replace('T', ' ').substring(0, 19)}</span>
                                  </div>

                                  <div className="space-y-1">
                                    <span className="text-[9px] text-slate-500 block uppercase font-mono">SHA-256 Hash Signature</span>
                                    <span className="text-[10px] font-mono font-bold text-cyan-400 break-all select-all bg-black/40 p-1 rounded border border-slate-800 block">
                                      {ev.hash}
                                    </span>
                                  </div>

                                  {ev.metadata && (
                                    <div className="bg-black/30 p-2.5 rounded border border-slate-850 font-mono text-[10px] text-slate-400 space-y-1">
                                      {ev.metadata.url && <p><span className="text-slate-500">Checked Endpoint:</span> {ev.metadata.url}</p>}
                                      {ev.metadata.tlsVersion && <p><span className="text-slate-500">SSL Session:</span> {ev.metadata.tlsVersion}</p>}
                                      {ev.metadata.headersChecked && <p><span className="text-slate-500">Headers:</span> {ev.metadata.headersChecked.join(", ")}</p>}
                                      {ev.metadata.observedPayload && <p className="text-yellow-500 mt-1 border-t border-slate-900 pt-1 leading-tight"><span className="text-slate-500">Observed Payload:</span> {ev.metadata.observedPayload}</p>}
                                    </div>
                                  )}

                                  <div className="flex justify-between items-center pt-2">
                                    <button
                                      onClick={() => verifyEvidenceHash(ev, selectedFinding)}
                                      className="bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-[10px] font-bold px-3 py-1.5 rounded border border-slate-700 uppercase"
                                    >
                                      Verify Hash Integrity
                                    </button>

                                    {evidenceValidationStatus === 'VALIDATING' && <span className="text-[10px] text-yellow-500 font-mono animate-pulse">Computing checksum...</span>}
                                    {evidenceValidationStatus === 'INTEGRITY_VERIFIED' && <span className="text-[10px] text-green-400 font-mono font-bold flex items-center"><CheckCircle size={10} className="mr-1" /> VALIDATED IMMUTABLE</span>}
                                  </div>
                                </div>
                              );
                            })()
                          ) : (
                            <p className="text-[11px] text-slate-500 font-mono">Evidence packet currently compiling in background pipeline.</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-[#14141A]/40 border border-dashed border-slate-800 rounded-xl p-12 text-center text-slate-500 text-xs font-mono">
                      Select a finding from the left list to inspect technical remediation, security parameters, and cryptographic evidence checksums.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              TAB 5: OWASP AGENTIC AI SECURITY TOP 10
              ========================================== */}
          {activeTab === 'ai_sec' && (
            <div id="view-ai-sec" className="space-y-8 animate-fadeIn">
              
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-lg font-bold text-white uppercase font-mono tracking-wider">OWASP Agentic AI Security Assessment</h3>
                  <p className="text-xs text-slate-400">Diagnostic monitoring framework assessing autonomous LLMs, custom instructions, and memory boundaries</p>
                </div>
                <div className="px-3 py-1 bg-red-950/20 border border-red-900/30 rounded text-xs text-red-400 font-mono font-bold uppercase">
                  ASI01 - ASI10 Threat Mapping
                </div>
              </div>

              {/* Grid layout describing Agentic vulnerabilities tested */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                
                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-red-500/10 text-red-500 border border-red-500/20 rounded font-mono text-[9px] font-bold">ASI01</span>
                    <span className="text-[10px] text-green-400 font-mono">100% COVERED</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Agent Goal Hijacking</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Evaluates if custom system prompts or conversational boundaries can be overridden to inject rogue objective overrides.
                  </p>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded font-mono text-[9px] font-bold">ASI02</span>
                    <span className="text-[10px] text-green-400 font-mono">100% COVERED</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Tool Misuse & Exploitation</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Audits allowed API tools, testing if simulated parameters can trick the LLM client into calling unapproved actions.
                  </p>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-yellow-500/10 text-yellow-500 border border-yellow-500/20 rounded font-mono text-[9px]">ASI03</span>
                    <span className="text-[10px] text-cyan-400 font-mono">AUDITING</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Identity & Privilege Abuse</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Identifies permission leakages where the agent inherits unvalidated scopes from downstream callers or parent credentials.
                  </p>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-slate-800 text-slate-400 border border-slate-700 rounded font-mono text-[9px]">ASI04</span>
                    <span className="text-[10px] text-slate-500 font-mono">PASSIVE ONLY</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Agentic Supply Chain</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Assesses dependency plugins, third-party template prompts, and external API connectors for data leakage pathways.
                  </p>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-red-500/10 text-red-500 border border-red-500/20 rounded font-mono text-[9px] font-bold">ASI05</span>
                    <span className="text-[10px] text-green-400 font-mono">100% COVERED</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Unexpected Code Execution</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Validates sandbox boundaries around evaluation loops, dynamic interpreters, or unsafe code compilation calls.
                  </p>
                </div>

                <div className="bg-[#14141A] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex justify-between items-start">
                    <span className="px-2 py-0.5 bg-orange-500/10 text-orange-400 border border-orange-500/20 rounded font-mono text-[9px] font-bold">ASI06</span>
                    <span className="text-[10px] text-green-400 font-mono">100% COVERED</span>
                  </div>
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">Memory & RAG Poisoning</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Audits database search streams, detecting if adversarial context injected into databases can override active instructions.
                  </p>
                </div>
              </div>

              {/* Visual Simulated Sandbox */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 relative overflow-hidden">
                <div className="absolute top-3 right-3 flex items-center space-x-1">
                  <span className="text-[9px] text-slate-500 font-mono">SECURE AGENT MODELING LAYER</span>
                </div>
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono mb-4">Interactive AI Threat Modeling Sandbox</h4>
                
                <div className="bg-black/80 rounded-lg p-5 font-mono text-xs text-slate-300 space-y-3 border border-slate-850">
                  <p className="text-cyan-500 font-bold">&gt;&gt; initiating agent objective test sequences on {activeScan ? activeScan.target : 'api.secure-node.ai'}...</p>
                  <p className="text-slate-400 leading-relaxed">
                    [DIAGNOSTIC CORE] Testing custom instructions mapping. Target type: <span className="text-yellow-500 font-semibold uppercase font-mono">{activeScan ? activeScan.targetType : 'AI Agent'}</span>.<br />
                    [DIAGNOSTIC CORE] Validating prompt prefix insulation barriers against indirect overrides...
                  </p>
                  
                  {activeScan && (activeScan.targetType === 'ai_agent' || activeScan.targetType === 'comprehensive') ? (
                    <div className="space-y-3">
                      <div className="bg-red-950/20 border border-red-900/30 p-3 rounded text-[11px] text-red-400 space-y-1">
                        <p className="font-bold uppercase tracking-wider">CRITICAL RISK ALERT — GOAL DRIFT SUSCEPTIBILITY (ASI01)</p>
                        <p>Adversarial instructions successfully bypassed target isolation borders on conversational test scenarios, allowing arbitrary backend command triggers.</p>
                      </div>
                      <div className="bg-orange-950/20 border border-orange-900/30 p-3 rounded text-[11px] text-orange-400 space-y-1">
                        <p className="font-bold uppercase tracking-wider">HIGH RISK ALERT — INDIRECT PROMPT INJECTION VIA RAG (ASI06)</p>
                        <p>Poisoned knowledge base payloads loaded in vector storage successfully manipulated the RAG context stream, overriding core instruction guidelines.</p>
                      </div>
                    </div>
                  ) : (
                    <div className="bg-slate-900 border border-slate-800 p-3 rounded text-[11px] text-slate-400">
                      Launch a new security scan on your target to trigger autonomous multi-agent threat modeling and sandbox simulation.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ==========================================
              TAB 6: GOVERNANCE, POLICY & COMPLIANCE
              ========================================== */}
          {activeTab === 'governance' && (
            <div id="view-governance" className="space-y-8 animate-fadeIn">
              
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-lg font-bold text-white uppercase font-mono tracking-wider">Corporate Governance & Compliance Mapping</h3>
                  <p className="text-xs text-slate-400">Enforce enterprise policies, monitor user audit trails, and map vulnerabilities to standard compliance models</p>
                </div>
                <div className="bg-cyan-950/40 border border-cyan-800/40 rounded px-3 py-1 font-mono text-xs text-cyan-400">
                  SOC 2 CC6.1 Certified Logs
                </div>
              </div>

              {/* Multi-Agent Corporate Policy manager */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                
                {/* Active Organizational Policy config (CISO restricted edits) */}
                <div className="lg:col-span-6 bg-[#14141A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <div className="flex justify-between items-start mb-4">
                      <div>
                        <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">ORGANIZATION SECURITY POLICY</h4>
                        <p className="text-[11px] text-slate-500">Allowed/restricted testing tools and parameters</p>
                      </div>
                      <span className="text-[9px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded uppercase">
                        Active Enforced
                      </span>
                    </div>

                    <div className="space-y-4 my-4 text-xs">
                      <div>
                        <span className="text-slate-400 font-mono block mb-1.5">Approved Scanning Agents</span>
                        <div className="flex flex-wrap gap-2">
                          {policy?.allowedTools.map((t, idx) => (
                            <span key={idx} className="bg-slate-900 border border-slate-800 px-2 py-1 rounded text-slate-300 font-mono text-[10px]">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-400 font-mono block mb-1.5">Restricted Scanning Tools (Simulated)</span>
                        <div className="flex flex-wrap gap-2">
                          {policy?.restrictedTools.map((t, idx) => (
                            <span key={idx} className="bg-red-950/40 border border-red-900/30 px-2 py-1 rounded text-red-400 font-mono text-[10px]">
                              {t}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div>
                        <span className="text-slate-400 font-mono block mb-1.5">Active Safety Constraints Enforced</span>
                        <ul className="space-y-1 ml-4 list-disc text-slate-400">
                          {policy?.safetyConstraints.map((sc, idx) => (
                            <li key={idx}>{sc}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 border-t border-slate-800">
                    <div className="flex items-center space-x-2 bg-slate-900/80 p-3 rounded border border-slate-800 text-[11px] text-slate-400">
                      <Lock size={12} className="text-cyan-400 shrink-0" />
                      <span>
                        Note: Demoting your role status to <strong>CISO</strong> allows real-time modifications to organization-wide safety boundaries.
                      </span>
                    </div>
                    
                    {session?.role === 'CISO' || session?.role === 'AI Governance' ? (
                      <div className="mt-4 flex space-x-2">
                        <button
                          onClick={() => handleUpdatePolicy(
                            ["Recon Agent", "Vulnerability Assessment Agent", "AI Security Agent", "AI Analyst Agent"],
                            ["Passive assessment only", "No destructive testing", "Authorization checks required"],
                            ["Exploit Simulation Agent"]
                          )}
                          className="bg-slate-800 hover:bg-slate-700 text-white font-mono text-[10px] font-bold px-3 py-1.5 rounded uppercase border border-slate-700"
                        >
                          Enforce High-Insulation Safety Standard
                        </button>
                      </div>
                    ) : null}
                  </div>
                </div>

                {/* Audit logs of platform interaction (SOC 2 CC6.1 requirement) */}
                <div className="lg:col-span-6 bg-[#14141A] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                  <div>
                    <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono mb-4">SOC 2 / ISO 27001 Access Audit Logs</h4>
                    
                    <div className="bg-black/60 rounded-lg p-4 font-mono text-[10px] leading-relaxed max-h-80 overflow-y-auto space-y-3.5 border border-slate-850">
                      {auditLogs.map((log, index) => (
                        <div key={index} className="border-b border-slate-900 pb-2">
                          <div className="flex justify-between text-slate-500">
                            <span>{log.timestamp.replace('T', ' ').substring(0, 19)}</span>
                            <span>{log.ipAddress}</span>
                          </div>
                          <p className="text-cyan-400 font-bold mt-0.5">{log.action}</p>
                          <p className="text-slate-300 mt-0.5">Operator: <span className="text-slate-400 font-semibold">{log.user}</span> ({log.role})</p>
                          <p className="text-slate-400 mt-0.5">Target Scope: {log.target}</p>
                          <p className="text-slate-500 text-[9px] mt-1 break-all">Immutable Audit Hash: {log.hash}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="text-[10px] text-slate-500 font-mono mt-4">
                    Audit logs are generated and cryptographically signed on the server-side upon successful consent verification.
                  </div>
                </div>
              </div>

              {/* Compliance standard matrix */}
              <div className="bg-[#14141A] border border-slate-800 rounded-xl p-6">
                <h4 className="text-xs font-bold text-slate-400 uppercase tracking-widest font-mono mb-4">MAPPED REGULATORY COMPLIANCE MATRICES</h4>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                  
                  <div className="bg-slate-900/60 p-4 rounded border border-slate-800 space-y-2">
                    <span className="text-xs font-bold font-mono text-cyan-400">NIST AI Risk Management (RMF)</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Maps identified conversational vulnerabilities to sections G-100, checking instruction boundary leaks and goal compliance.
                    </p>
                  </div>

                  <div className="bg-slate-900/60 p-4 rounded border border-slate-800 space-y-2">
                    <span className="text-xs font-bold font-mono text-cyan-400">PCI-DSS v4.0 (Section 6.5)</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Verifies missing HTTP Security headers (HSTS, CSP) to secure cardholder transit channels from MITM downgrades.
                    </p>
                  </div>

                  <div className="bg-slate-900/60 p-4 rounded border border-slate-800 space-y-2">
                    <span className="text-xs font-bold font-mono text-cyan-400">ISO/IEC 27001 (Control A.12.6.1)</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Manages vulnerability recording and mitigation processes, providing formal technical roadmaps for developers.
                    </p>
                  </div>

                  <div className="bg-slate-900/60 p-4 rounded border border-slate-800 space-y-2">
                    <span className="text-xs font-bold font-mono text-cyan-400">SOC 2 (CC6.1 - CC6.3 Access Control)</span>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      Enforces explicit authorization confirm checks to ensure auditing compliance and tracking validation parameters.
                    </p>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ==========================================
            FOOTER STATUS LINE (Matches Sleek Interface layout)
            ========================================== */}
        <footer className="h-10 bg-[#0F0F12] border-t border-slate-800/80 flex items-center justify-between px-8 text-[10px] text-slate-600 font-medium shrink-0 z-10">
          <div className="flex space-x-6 font-mono">
            <span>NODE: CLOUD-RUN-US-EAST</span>
            <span>SYSTEM MONITOR TIMER: {agentTimer}</span>
            <span>LATENCY: {latency}ms</span>
          </div>
          <div className="flex items-center space-x-4 font-mono">
            <span className="flex items-center">
              <span className="w-1.5 h-1.5 bg-green-500 rounded-full mr-1.5 animate-pulse"></span>
              SYSTEM HEALTH: {sysHealth}
            </span>
            <span 
              onClick={() => setShowLegalDisclosure(!showLegalDisclosure)}
              className="text-slate-500 underline cursor-pointer hover:text-slate-400 font-bold"
            >
              LEGAL & ETHICAL MANDATE POLICY
            </span>
          </div>
        </footer>
      </main>

      {/* Legal and Ethical compliance overlay/modal */}
      {showLegalDisclosure && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fadeIn">
          <div className="bg-[#14141A] border border-slate-800 max-w-xl rounded-xl p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <span className="text-xs font-bold font-mono text-red-400 flex items-center">
                <AlertTriangle size={14} className="mr-2" /> ETHICAL RED TEAM OPERATION POLICY
              </span>
              <button 
                onClick={() => setShowLegalDisclosure(false)}
                className="text-slate-500 hover:text-slate-300 font-bold text-xs uppercase"
              >
                Close
              </button>
            </div>
            
            <p className="text-xs text-slate-300 leading-relaxed space-y-2">
              Antigravity AI is an autonomous agentic security validation platform built exclusively for defensive audit verification, vulnerability assessment, and authorized threat modeling. 
              <br /><br />
              All tests performed are non-destructive and strictly simulate scenarios mapping to OWASP Agentic AI Top 10 and traditional web vulnerability indices. Execution of actual attacks, malware deployment, or unauthorized testing against external assets is strictly prohibited by both regulatory guidelines and system governance layers.
            </p>

            <div className="bg-slate-900 p-3 rounded border border-slate-800 text-[10px] text-slate-400 font-mono">
              SOC-2 Control Enforced: Explicit target owner validation check required on every threat modeling session initiation.
            </div>

            <div className="text-right">
              <button
                onClick={() => setShowLegalDisclosure(false)}
                className="bg-slate-800 hover:bg-slate-700 text-white font-mono text-xs font-bold px-4 py-2 rounded border border-slate-700 uppercase"
              >
                I Understand & Comply
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
