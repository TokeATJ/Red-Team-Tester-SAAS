# Regulatory & Compliance Framework Mapping

The **Agentic AI Security Audit Platform** does not issue certifications. Instead, it provides **alignment support** and **automated evidence mapping** to accelerate compliance reporting for modern web and AI-native enterprise architectures.

---

## Compliance Reference Matrix

The following table maps findings from our platform's telemetry to specific controls across global compliance frameworks:

| Mapped Finding | NIST Cybersecurity Framework 2.0 (CSF) | ISO/IEC 27001:2022 Control Reference | SOC 2 Trust Services Criteria (TSC) | OWASP LLM / Agentic AI Vulnerability | NIST AI Risk Management Framework (AI RMF) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Missing Content-Security-Policy Header** | **PR.DS-01**: Data-at-rest and in-transit are protected. | **A.8.28**: Secure Coding | **CC7.1**: Infrastructure & Vulnerability Management | *N/A (Web Tier Control)* | **Measure 2.11**: Robustness & Security |
| **Exposed Verbose Debug Stack Traces** | **DE.AE-01**: Detection processes are maintained. | **A.8.20**: Network Security | **CC7.2**: Security Monitoring & Analysis | *N/A (Web Tier Control)* | **Govern 1.2**: System Boundaries |
| **ASI01 — Cognitive Intent Override** | **PR.IP-01**: Security policies are maintained. | **A.8.28**: Secure Coding | **CC6.1**: Authorization & Boundary Access | **ASI01**: Dynamic Intent Drift and Instruction Overrides | **Govern 1.2**: System Boundaries |
| **ASI06 — Indirect Prompt Injection via RAG** | **PR.DS-01**: Data-at-rest and in-transit are protected. | **A.8.24**: Use of Cryptography / Secure Data Ingestion | **CC6.1**: Authorization & Boundary Access | **ASI06**: Indirect Prompt Injection / Context Poisoning | **Measure 2.11**: Robustness & Security |

---

## Alignment Descriptions

### SOC 2 Trust Services Criteria (CC6.0 & CC7.0)
Our reports focus on verifying logical access boundaries and system vulnerability management:
* **Boundary Validation**: Proving that unauthorized inputs cannot bypass authentication barriers or model instructions to call administrative functions (aligned with CC6.1).
* **System Monitoring**: Logging every step of the testing process with timestamped, agent-labeled log strings to demonstrate operational control (aligned with CC7.2).

### ISO/IEC 27001:2022 (Controls A.8.20 & A.8.28)
* **Secure Coding**: Delivering immediate, contextual TypeScript and configuration remediation blueprints to enforce secure development policies (aligned with A.8.28).
* **Network & Information Security**: Monitoring response headers to verify that transport-layer isolation controls are configured across all public routes (aligned with A.8.20).

### NIST AI Risk Management Framework 1.0
* **System Boundaries**: Verifying that AI agents maintain strict alignment with their operational directives and do not drift into unauthorized system commands (aligned with Govern 1.2).
* **Robustness & Security**: Identifying indirect prompt-injection vectors that could contaminate RAG indices and lead to data leaks or phishing exploits (aligned with Measure 2.11).
