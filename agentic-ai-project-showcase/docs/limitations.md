# Platform Boundaries & Intended Limitations

To maintain a secure, compliant, and highly stable operational footprint, the **Agentic AI Security Audit Platform** operates under strict technical and behavioral boundaries.

---

## 1. Non-Destructive Vulnerability Modeling
* **Passive Focus**: The platform is explicitly designed to identify, analyze, and map security vulnerabilities without executing destructive or service-disrupting payloads (e.g., active SQL database deletion, privilege escalation execution, or resource depletion).
* **Simulated Exploits**: When demonstrating vulnerabilities like CORS misconfigurations, API stack trace leaks, or cognitive AI overrides, the platform uses non-destructive, isolated probing strings. It models the *existence* of the vulnerability rather than weaponizing it.

---

## 2. Local Scope and Authorization Dependencies
* **Explicit Authorization Required**: The Intake Agent blocks any scanning operations targeting domains or systems where ownership cannot be verified or authenticated.
* **WAF/Firewall Limits**: Because the Vulnerability Assessment Agent relies on standard HTTP requests, high-security Cloud Web Application Firewalls (such as Cloudflare or AWS WAF) may throttle, block, or mask probe results. This is expected and serves as evidence of an active boundary defense.

---

## 3. Human-in-the-Loop Dependency
* **Remediation Suggestion Only**: The system does not write code changes directly to target production environments.
* **No Direct Patching**: All technical fixes (e.g., Content-Security-Policy injection, Express exception handler updates) are presented as technical blueprints that require manual review and deployment by authorized engineering personnel.

---

## 4. Model Determinism and Alignment
* **Cognitive Probability**: Because cognitive assessments rely on advanced Large Language Models, findings mapping AI-specific vulnerabilities (like ASI01 or ASI06) are based on probabilistic threat modeling. While highly accurate, they reflect risk-modeling assessments rather than traditional deterministic bitwise checks.
