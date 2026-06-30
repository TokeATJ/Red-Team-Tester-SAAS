# Multi-Agent Assessment Workflows

This document illustrates the execution workflows and message coordination patterns used within the platform to transition from an initial scan request to an audit-ready compliance report.

## End-to-End Execution Sequence

```
User (UI)       Intake Agent      Recon Agent      Vulnerability Agent      AI Exploitation Agent      Security Agent      Human Reviewer
   │                  │                │                   │                         │                     │                   │
   │───[Start Scan]──>│                │                   │                         │                     │                   │
   │                  │───[Verify]────>│                   │                         │                     │                   │
   │                  │   Auth Limits  │                   │                         │                     │                   │
   │                  │                │───[Run DNS Probs]─>                         │                     │                   │
   │                  │                │   Intelligence    │                         │                     │                   │
   │                  │                │                   │───[Run HTTP Probes]────>│                     │                   │
   │                  │                │                   │   Isolation Headers     │                     │                   │
   │                  │                │                   │                         │───[Fuzz Cognitive]─>│                   │
   │                  │                │                   │                         │   & Prompt Overrides│                   │
   │                  │                │                   │                         │                     │───[Generate Map]─>│
   │                  │                │                   │                         │                     │   Report & Checks │
   │                  │                │                   │                         │                     │                   │───[Approve]───┐
   │                  │                │                   │                         │                     │                   │   Remediate   │
   │                  │                │                   │                         │                     │                   │   & Sign Logs │
   │<──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────│   Report      │
   │                                              [Immutable Cryptographic GRC Report Delivered] <─────────────────────────────┘
```

---

## Step-by-Step Workflow Breakdown

### Phase 1: Initiation and Gatekeeping
1. **Request Reception**: The operator initiates a scan via the React UI, submitting the target metadata.
2. **Permission Check**: The **Intake Agent** intercepts the request, runs local database validation queries, and verifies that the operator possesses authenticated permissions for the target scope.

### Phase 2: Passive Information Gathering
3. **DNS Intelligence Resolution**: The **Recon Agent** performs passive DNS lookups to construct target IP maps, routing paths, and host record sets, publishing structured JSON logs.

### Phase 3: Transport Layer Probing
4. **Endpoint Validation**: The **Vulnerability Assessment Agent** fires isolated HTTP probing checks to check response headers, looking for security headers (like Content-Security-Policy or Access-Control-Allow-Origin).

### Phase 4: Cognitive Boundary Stress Testing
5. **AI Exploitation Assessment**: The **AI Exploitation Agent** validates prompt-handling pipelines. It models cognitive threat vectors—such as goal hijacking or context poisoning—against simulated configurations to determine if administrative rules can be bypassed.

### Phase 5: GRC Synthesis and Remediation Generation
6. **Compliance Mapping**: The **Security Review Agent** gathers all finding payloads, calculates risk ratings, maps them to regulatory controls (SOC 2, ISO 27001), and generates custom code-level remediation blocks.

### Phase 6: Human Approval and Audit Signing
7. **Operator Verification**: The resulting findings are held in a pending state until a human operator reviews the remediation suggestions.
8. **Cryptographic Signing**: Once verified, the system generates an immutable SHA-256 signature block, certifying the report's compliance integrity.
