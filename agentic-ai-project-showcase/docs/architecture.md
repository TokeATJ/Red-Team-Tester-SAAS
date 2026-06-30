# High-Level System Architecture

This document describes the conceptual, multi-layer architecture of the **Agentic AI Security Audit Platform**. The architecture is structured to enforce strong boundary isolation, high performance, and tamper-proof audit trails.

## Functional Architecture Layers

```
┌────────────────────────────────────────────────────────────────────────┐
│                        User Interface Layer                            │
│    (React Web Portal, Telemetry Streams, GRC Finding Dashboard)        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Secure Session Tokens
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        API & Service Layer                             │
│     (Express API Router, Scan Coordinator, Authorization Engines)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
         ┌──────────────────────────┴──────────────────────────┐
         ▼                                                     ▼
┌──────────────────────────────────┐         ┌──────────────────────────────────┐
│     Orchestration Layer          │         │     Tool Execution Layer         │
│  (Multi-Agent Decision Core,     │         │ (Isolated Sandboxed Workers,     │
│   Gemini API Cognitive Engine)   │         │  DNS & HTTP Probing Utilities)   │
└────────────────┬─────────────────┘         └─────────────────┬────────────────┘
                 │                                             │
                 └──────────────────────┐ ┌────────────────────┘
                                        ▼ ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Policy & Guardrail Layer                       │
│    (Input/Output Sanitizers, Intent Classifiers, Schema Validators)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Validated Context Chunks
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         Memory & Audit Layer                           │
│ (Transient Session Cache, Secure JSON Storage, Cryptographic Hasher)   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Architectural Breakdown

### 1. User Interface Layer
A high-performance single-page web client built in React. It renders:
* Real-time streaming log telemetry from active agent workers.
* Interactive, filterable dashboard of mapped vulnerabilities.
* The Remediation Playground, showing code changes and cryptographic integrity blocks.

### 2. API & Service Layer
The Express-based gateway server manages session handshakes, coordinates scanning lifecycle hooks, and enforces human-in-the-loop validation barriers.

### 3. Agent Orchestration Layer
The brain of the platform. Rather than relying on a single general-purpose prompt, it directs a pipeline of highly specialized, task-constrained AI agents (such as the Recon, Vulnerability Assessment, and AI Exploitation Agents).

### 4. Tool Execution Layer
Contains the safe, read-only utilities used by agents to gather telemetry:
* **DNS Intelligence Resolver**: Resolves host routing vectors safely.
* **HTTP Prober**: Inspects remote web response headers to flag isolation deficiencies.
* **Cognitive Fuzzing Drivers**: Generates isolated, safe boundary prompts to model injection risks.

### 5. Policy & Guardrail Layer
Enforces input sanitization and output structural compliance. This layer checks all outgoing LLM requests and incoming tool responses to prevent injection leaks.

### 6. Memory & Audit Layer
Ensures session isolation. All findings and scan telemetry are compiled into structured JSON data models and assigned immutable SHA-256 verification hashes for compliance traceability.
