# ANTIGRAVITY AI — AUTONOMOUS RED TEAM & AGENTIC AI SECURITY PLATFORM

Antigravity AI is an enterprise-grade SaaS platform built to automate authorized security validation, Attack Surface Management (ASM), and Agentic AI Security Auditing. The platform combines passive intelligence gathering, non-destructive threat simulation modeling, and server-side reasoning engines powered by Gemini AI models to map complex threat paths.

---

## 1. ARCHITECTURE OVERVIEW

Antigravity AI utilizes a modern, robust, full-stack architecture combining a reactive TypeScript frontend styled after the premium **"Sleek Interface"** design paradigm with a secure Node.js (Express) backend.

```
+--------------------------------------------------------------------------+
|                              ANTIGRAVITY FRONTEND                         |
|    [Executive Dashboard]  [Attack Surface]  [Governance & Compliance]     |
|    [Active Scan Console]  [Evidence Vault]  [OWASP Agentic AI Monitor]   |
+------------------------------------+-------------------------------------+
                                     |
                                     | Secure API Handshakes (REST/JSON)
                                     v
+------------------------------------+-------------------------------------+
|                              ANTIGRAVITY BACKEND                          |
|    * Multi-Agent Coordinator Core                                        |
|    * Passive Port & Header Inspect Hook                                  |
|    * STRIDE & MITRE ATT&CK Mapper Engine                                 |
|    * Google GenAI Integration Proxy (Lazy Loaded)                        |
|    * SOC-2 Compliance Audit Signer                                       |
+--------------------------------------------------------------------------+
```

---

## 2. MULTI-AGENT ARCHITECTURE & WORKFLOW

The scanning core deploys five distinct task-specific agents in a synchronized, linear pipeline to audit the specified target:

1. **Recon Agent**: Conducts asynchronous passive DNS checks and server header analysis.
2. **Vulnerability Assessment Agent**: Safely checks for transport weaknesses (weak TLS, missing HSTS, missing CSP, insecure cookies).
3. **Exploit Simulation Agent**: Safely models input validation or endpoint escape paths under strict governance constraints.
4. **AI Security Agent**: Evaluates targeted LLM endpoints against the **OWASP Agentic AI Top 10 (ASI01 - ASI10)**.
5. **AI Analyst Agent**: Integrates server-side Gemini threat modeling to generate risk scores, technical mitigations, and compliance mappings.
6. **Report Generation Agent**: Formats results into structured text bundles ready for leadership (CISO), engineering, or compliance audits.

---

## 3. THREAT MODELS & SEQUENCE DIAGRAMS

### STRIDE Threat Model
* **Spoofing**: Enforces strict DNS resolution matching and server-side hostname verification to prevent domain hijacking.
* **Tampering**: All evidence collected includes a calculated SHA-256 hash checksum, allowing operators to run instant integrity checks in the Evidence Vault.
* **Repudiation**: A robust Audit Log records all actions with timestamps, operator emails, confirmation signatures, and client IP addresses.
* **Information Disclosure**: Lazy-loads Gemini credentials. Secrets are excluded from logs and browser visibility.
* **Denial of Service**: Passive assessment models apply strict rate limits to prevent scanning-induced performance degradation.
* **Elevation of Privilege**: Enforces front-to-back Role Based Access Controls (RBAC) preventing unauthorized users from modifying governance policies.

### Sequence Diagram: Consent & Scan Loop
```
Operator (UI)          Node Controller            Recon / AI Agent           Gemini Model
    |                         |                          |                         |
    |-- Click Start Scan ---->|                          |                         |
    |   [Checks Consent]      |                          |                         |
    |                         |-- Parse & SSRF Check --->|                         |
    |                         |-- Write Audit Trail ---->|                         |
    |<-- Return Scan ID ------|                          |                         |
    |                         |-- Trigger Pipeline ----->|                         |
    |                         |                          |-- HTTP GET / passive -->|
    |                         |                          |-- Evaluate ASI01-10 --->|
    |                         |                          |                         |
    |                         |<-- Pipe raw headers -----|                         |
    |                         |                                                    |
    |                         |-- Post threat intelligence parameters ------------>|
    |                         |<-- Synthesized risk scores & CVSS maps -------------|
    |                         |
    |<-- Event Stream logs ---|
    v                         v
```

---

## 4. DATABASE MODELS (In-Memory / Persistent Schemas)

The platform maintains rich, typed state models mapped to the following entities:

* **UserSession**: Tracks active operator parameters, roles (`CISO`, `Security Analyst`, `Security Engineer`, `AI Governance`), and organization labels.
* **Scan**: Contains metadata, target types (`ai_agent`, `rag_app`, `api_endpoint`, `standard_web`), overall risk metrics, and logs.
* **Finding**: Technical threat records detailing descriptions, impact analysis, STRIDE categories, and mitigation advice.
* **Evidence**: Stores raw HTTP check metadata, cryptographic hashes, and integrity status fields.
* **OrganizationPolicy**: Controls tool restrictions and active safety boundaries.
* **AuditRecord**: Signed immutable logs representing administrative actions.

---

## 5. DOCKER CONFIGURATION

Deploy Antigravity AI safely using isolated, non-privileged Docker configurations:

```dockerfile
# Dockerfile
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --only=production
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/server.ts ./server.ts
COPY --from=builder /app/src/types.ts ./src/types.ts
RUN npm install -g tsx

EXPOSE 3000
USER node
CMD ["tsx", "server.ts"]
```

---

## 6. ETHICAL COMPLIANCE & LEGAL SAFETY

Antigravity AI enforces security constraints to prevent abuse:
1. **SSRF Protections**: Targets resolving to local addresses (`localhost`, `127.0.0.1`, loopbacks) are immediately blocked.
2. **Authorization Consent Check**: Initiators must confirm ownership before scans are queued.
3. **Passive Auditing**: The scanning engine utilizes only standard GET, HEAD, and passive DNS lookups. No exploits or hostile code are deployed.
