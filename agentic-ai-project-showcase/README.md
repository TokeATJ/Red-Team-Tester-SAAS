# 🚀 Antigravity Agentic Security Auditor & Threat Simulation Engine

<p align="center">
  <img src="demos/screenshots/hero_banner.jpg" alt="Antigravity Security Audit Banner" width="100%" referrerPolicy="no-referrer" />
</p>

⚠️ **This repository is a technical showcase.**
The production system runs in a private, secured environment.
Source code is intentionally excluded to protect intellectual property, security-sensitive logic, and enterprise deployment patterns.

---

## 1. Executive Summary

The **Antigravity Agentic Security Auditor & Threat Simulation Engine** represents a paradigm shift in continuous Security Audit and GRC (Governance, Risk, and Compliance) automation. Powered by a coordinated network of autonomous, specialized AI agents, Antigravity automates passive reconnaissance, DNS intelligence mapping, secure transport probing, and deep-context vulnerability assessments. 

Designed for cloud-native architectures and AI-integrated pipelines, the engine stress-tests and audits both standard web vulnerabilities and complex AI-specific threats (such as the **OWASP Top 10 for LLM Applications** and the **OWASP Agentic AI Risks (ASI01–ASI10)**). It transforms raw, complex exploit simulations into certified compliance artifacts mapped to global security frameworks (**SOC 2, ISO 27001, NIST CSF 2.0, NIST AI RMF**), complete with cryptographic validation ledgering and interactive code-level remediation.

---

## 2. Problem Statement

### The Security Gap
As organizations adopt autonomous AI agents and Large Language Models, traditional Application Security Testing (AST) tools are failing. Traditional vulnerability scanners operate on static, deterministic signatures; they are fundamentally blind to **cognitive vulnerabilities**—including instruction drift, prompt hijack attempts, goal overrides, and RAG index contamination.

### Why Existing Solutions Fail
1. **Lack of AI Context**: Traditional scanners analyze network handshakes and input boundaries but cannot evaluate the semantic and cognitive boundaries of LLM prompt layers.
2. **Actionability Deficit**: Compliance tools flag risks but leave engineering teams to manually design and write complex custom sanitization code and response headers.
3. **The Audit Proof Bottleneck**: Converting technical logs into audit-acceptable evidence is a manual, labor-intensive process that stalls compliance cycles.

### Risks of Inaction
Deploying AI agents without automated cognitive security boundaries leaves organizations exposed to data exfiltration, system takeover, brand reputation collapse, and immediate non-compliance penalties under the latest enterprise regulations.

---

## 3. Solution Overview

Antigravity unites automated security probing, cognitive threat modeling, and immediate, cryptographically validated code-level remediation into a single, cohesive, multi-agent pipeline.

### Key Capabilities
* **Multi-Agent Orchestration**: Coordinates a team of specialized AI agents, ensuring compartmentalized task execution and predictable reasoning loops.
* **Passive & Safe Assessments**: Gathers deep security intelligence without launching invasive, destructive, or service-disrupting payloads.
* **GRC Automation Engine**: Automatically translates raw vulnerability logs into highly structured compliance evidence documents mapped directly to global standards.
* **Remediation Code Blueprinting**: Delivers precise, copy-pasteable TypeScript, Express middleware, and server configurations tailored to the exact context of each finding.

---

## 4. Core Features & Tool Usage

Antigravity delivers real-time control, high-fidelity monitoring, and deep technical insights through a sleek, interactive operator terminal.

<p align="center">
  <img src="demos/screenshots/dashboard_screenshot.jpg" alt="Antigravity Multi-Agent Scan Control Panel" width="90%" style="border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.4);" referrerPolicy="no-referrer" />
</p>

### How the Tool is Used:
1. **Target Initialization**: The security analyst inputs a target hostname and selects the target compliance frameworks (e.g., SOC 2, ISO 27001, OWASP AI).
2. **Autonomous Execution**: Upon authorization, the orchestrator dispatches specialized agent worker nodes. 
3. **Real-Time Telemetry**: Analysts track agent behavior in real time via a streaming terminal, monitoring active DNS mappings, transport-layer header logs, and simulated cognitive fuzzing outcomes.
4. **Interactive Risk Gauging**: Finding severities are aggregated and displayed as a combined CVSS-aligned risk score, offering instantaneous security posture feedback.

---

## 5. High-Value GRC Evidence & Remediation

The ultimate value of Antigravity lies in its ability to bridge the gap between technical finding identification and executive compliance resolution.

<p align="center">
  <img src="demos/screenshots/remediation_screenshot.jpg" alt="Antigravity GRC Evidence & Remediation Panel" width="90%" style="border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.4);" referrerPolicy="no-referrer" />
</p>

### Why This Information is Highly Valuable:
* **Accelerating developer remediation**: Instead of generic compliance advice, Antigravity generates exact, contextual before-and-after code modifications (such as strict Content-Security-Policy middleware or input schema sanitization blocks). This reduces patch times from days to minutes.
* **Satisfying GRC and Security Auditors**: Antigravity compiles structured, human-in-the-loop validated reports directly cross-referenced with official control requirements (e.g., CC7.1, A.8.28, SI-2).
* **Cryptographic Tamper-Proof Seals**: Completed reports are canonicalized and signed using SHA-256 cryptographic hashes. This enables compliance teams to immediately prove the absolute integrity and authenticity of their audit evidence packets.

---

## 6. Agentic AI Design

Antigravity coordinates multiple autonomous, specialized agents, each bound to a strict operational scope:

* **Intake Agent**: Verifies targeting permissions, checks RBAC authorization, and establishes targeting parameters.
* **Reconnaissance Agent**: Coordinates passive DNS intelligence and network architecture mapping.
* **Vulnerability Assessment Agent**: Probes remote endpoints to inspect HTTP secure transport isolation controls and CORS flags.
* **AI Exploitation Agent**: Stress-tests model prompting pipelines with safe, simulated cognitive fuzzing payloads.
* **Security & Compliance Agent**: Synthesizes telemetry logs, maps findings to compliance clauses, and compiles the code-level remediation blueprints.

Explore our [Agent Design Specifications](docs/agent-design.md) for full functional boundaries and escalation policies.

---

## 7. System Architecture & Trust Boundaries

The platform utilizes a layered architecture designed to enforce rigorous security boundary isolation:

```
                  ┌────────────────────────────────────────┐
                  │          React Web Portal Interface    │
                  └───────────────────┬────────────────────┘
                                      │ (Real-Time Streams)
                                      ▼
                  ┌────────────────────────────────────────┐
                  │      Express API & Gateway Controller  │
                  └───────────────────┬────────────────────┘
                                      │
         ┌────────────────────────────┴────────────────────────────┐
         ▼                                                         ▼
┌──────────────────────────────────┐             ┌──────────────────────────────────┐
│      LLM Orchestration Layer     │             │       Agent Execution Engine     │
│  (Gemini API with Guardrails)    │             │  (Isolated Tool Sandbox Workers) │
└──────────────────────────────────┘             └──────────────────────────────────┘
```

Detailed architectural breakdowns—including system boundaries, memory layers, and data validation boundaries—are documented in the [Architecture Guide](docs/architecture.md) and mapped visually in [System Diagrams](diagrams/system-architecture.md).

---

## 8. Security, Governance & Risk Management

Security is the core operating philosophy of Antigravity:
* **Principle of Least Privilege (PoLP)**: All tool workers execute within ephemeral, sandboxed containers, preventing access to host environments or unauthorized external networks.
* **Structured Output Schemas**: All agent communications are parsed via strict TypeScript interfaces, neutralising indirect prompt injection attacks before they can hijack reasoning streams.
* **Data Minimization and Redaction**: Logs are dynamically scanned and redacted prior to database persistence, ensuring no corporate secrets, system tokens, or personal identifiers are stored.

---

## 9. Compliance Alignment Matrix

| Mapped Finding | NIST CSF 2.0 | ISO/IEC 27001:2022 | SOC 2 (TSC) | OWASP LLM / Agentic AI | NIST AI RMF |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Missing CSP Response Header** | **PR.DS-01** | **A.8.28** | **CC7.1** | *N/A (Web Tier)* | **Measure 2.11** |
| **Exposed Verbose Stack Traces** | **DE.AE-01** | **A.8.20** | **CC7.2** | *N/A (Web Tier)* | **Govern 1.2** |
| **ASI01 — Cognitive Intent Override** | **PR.IP-01** | **A.8.28** | **CC6.1** | **ASI01** | **Govern 1.2** |
| **ASI06 — Indirect Prompt Injection** | **PR.DS-01** | **A.8.24** | **CC6.1** | **ASI06** | **Measure 2.11** |

Full alignments are mapped in the [Compliance Mapping Guide](docs/compliance-mapping.md).

---

## 10. Demo Scenarios

See how the multi-agent engine responds under diverse conditions:
1. **Scenario A: Web Portals & Transport Isolation Audit**: Probes host headers, audits CORS wildcards, and recommends secure Helmet middleware integrations.
2. **Scenario B: AI Chatbot Cognitive Bypass Auditing**: Tests conversational models against instruction overrides and prompts, identifying susceptibility to goal hijacking.
3. **Scenario C: Multi-Agent GRC Evidence compilation**: Demonstrates continuous logging, risk score computation, and cryptographic report signing.

Complete redacted logs and configurations are available in [Demo Scenarios](demos/demo-scenarios.md) and [Sample Input/Output](demos/sample-input-output.md).

---

## 11. Why the Source Code Is Private

To protect intellectual property and ensure the platform remains a defensive asset:
1. **Proprietary Prompt Envelopes**: System instructions are highly engineered to avoid hallucinations during security assessments.
2. **Pattern Matching & Threat Databases**: Signature catalogs for secure transport and CORS inspection are trade secrets.
3. **Enterprise Configurations**: Orchestration scripts, Docker structures, and cloud-native database schemas are withheld.

---

## 12. Request a Private Demo

We welcome serious inquiries from enterprise GRC teams, CISOs, prospective partners, and employers under a Mutual Non-Disclosure Agreement (MNDA).

📩 **Contact Channels**:
* **Email**: [tokeatijosan1@gmail.com](mailto:tokeatijosan1@gmail.com)
* **GitHub Profile**: [TokeATJ](https://github.com/TokeATJ)

---

## 13. Repository Map

* [📂 **docs/**](docs/)
  * [Overview & Vision](docs/overview.md) — Product scope and design pillars.
  * [System Architecture](docs/architecture.md) — Detailed layer-by-layer architectural breakdown.
  * [Agent Design](docs/agent-design.md) — Roles, inputs, outputs, and boundaries of active agents.
  * [Workflows](docs/workflows.md) — Step-by-step agent coordination and message streams.
  * [Security & Governance](docs/security-governance.md) — Least-privilege controls and prompt defenses.
  * [Compliance Mapping](docs/compliance-mapping.md) — Detailed cross-reference compliance tables.
* [📂 **diagrams/**](diagrams/)
  * [System Architecture](diagrams/system-architecture.md) — Mermaid visual map of the services.
  * [Agent Orchestration](diagrams/agent-orchestration.md) — Sequence flow of agent coordination.
  * [Data Flow](diagrams/data-flow.md) — Flow of telemetry from host to compiled audit proof.
  * [Trust Boundary](diagrams/trust-boundary.md) — Network and authentication boundary maps.
* [📂 **demos/**](demos/)
  * [Demo Scenarios](demos/demo-scenarios.md) — Operational walkthroughs.
  * [Sample Input/Output](demos/sample-input-output.md) — Redacted input and output JSON structures.
* [📂 **evidence/**](evidence/)
  * [Audit Artifacts](evidence/audit-artifacts.md) — Document structures for external auditors.
  * [Capability Metrics](evidence/metrics.md) — Core performance benchmarks.
  * [Performance Summary](evidence/performance-summary.md) — Asynchronous coordination and cryptographic validation details.
* [📂 **roadmap/**](roadmap/)
  * [Current State](roadmap/current-state.md) — Verified release capabilities.
  * [Future Enhancements](roadmap/future-enhancements.md) — Product vision and Q3/Q4 deliverables.

---

## 14. Disclaimer

*Disclaimer: This repository is intended strictly for portfolio presentation and architecture demonstration. The security scan findings, telemetry lines, and logs displayed in the documentation are simulated security validation examples designed to showcase GRC-mapping capabilities. No unauthorized scanning is ever performed. Always secure explicit authorization prior to testing production resources.*
