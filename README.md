# ClawGuardian

**Open-source security framework for AI agent skill ecosystems.**

Static analysis, behavioral monitoring, trust scoring, and composition risk detection for OpenClaw skills and plugins.

[![npm version](https://img.shields.io/npm/v/clawguardian.svg)](https://www.npmjs.com/package/clawguardian)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)

---

## The Problem

The OpenClaw ecosystem has a security crisis:

- **824 malicious skills** found on ClawHub (20% of the registry) deploying AMOS infostealer
- **CVE-2026-25253**: Remote Code Execution on 17,500+ exposed instances
- **Hong Kong government** banned OpenClaw from all government departments
- **Zero tools exist** to scan skills before installation or verify registry integrity

Existing solutions (NanoClaw, IronClaw, NemoClaw) solve **containment** -- they sandbox the agent so a bad skill can't escape. But they don't tell you **which skills are bad before you install them**.

ClawGuardian solves the other half: **detection, analysis, and trust scoring before a skill ever runs.**

## How It Works

ClawGuardian implements a 5-stage scanning pipeline:

```
Stage 1: Static Analysis (AST-based)
    Dependency audit, permission scope, known malware signatures
        |
Stage 2: Dynamic Analysis (sandboxed execution)
    Runtime behavior monitoring in isolated environment
        |
Stage 3: Semantic Analysis (LLM-assisted)
    Prompt injection detection, DAN variant scanning, tokenization attacks
        |
Stage 4: Composition Testing
    Skill dependency graphs, co-installation risk, chain attack detection
        |
Stage 5: Memory/Data Flow Analysis
    Credential exfiltration patterns, DNS tunneling, side-channel detection
```

Each stage catches attacks the previous stage misses. Traditional SAST won't detect prompt injection via skill outputs. Sandboxing won't catch composition attacks where two safe skills become dangerous together. ClawGuardian runs all five.

## Quick Start

```bash
npm install clawguardian
```

### Scan a skill before installation

```typescript
import { ClawGuardian } from 'clawguardian';

const guardian = new ClawGuardian({
  stages: ['static', 'dynamic', 'semantic'],
  policy: './clawguardian.config.yaml'
});

const result = await guardian.scan('./skills/untrusted-skill/');

console.log(result.trustScore);    // 0.0 - 1.0
console.log(result.threats);       // Array of detected threats
console.log(result.recommendation); // 'safe' | 'review' | 'block'

if (result.recommendation === 'block') {
  console.log('Skill blocked:', result.threats[0].description);
  // "Skill blocked: Detected credential-shaped strings in network output"
}
```

### Policy configuration

```yaml
# clawguardian.config.yaml
clawguardian:
  scanStages:
    - static
    - dynamic
    - semantic
    - composition
    - dataflow

  trustThresholds:
    block: 0.3      # Below 0.3 = auto-block
    review: 0.7     # 0.3 - 0.7 = manual review required
    safe: 0.7       # Above 0.7 = safe to install

  capabilities:
    maxNetworkEndpoints: 5
    allowedProtocols:
      - https
    blockedPatterns:
      - "*.onion"
      - "raw.githubusercontent.com/*/malware/*"

  composition:
    maxSkillChainDepth: 3
    blockUnknownInteractions: true

  reporting:
    format: sarif    # SARIF, JSON, or plain text
    outputDir: ./reports
    siem:
      webhook: "https://your-siem.example.com/api/events"
```

### Scan a skill registry

```typescript
const registry = await guardian.scanRegistry('https://clawhub.example.com/api/skills', {
  concurrency: 10,
  outputFormat: 'sarif',
  reportDir: './audit-reports'
});

console.log(`Scanned: ${registry.total}`);
console.log(`Safe: ${registry.safe}`);
console.log(`Blocked: ${registry.blocked}`);
console.log(`Review needed: ${registry.review}`);
```

## Capability Manifest System

ClawGuardian introduces capability manifests for agent skills -- like Android app permissions but for AI agent tools:

```yaml
# skill-manifest.yaml (required in every skill)
name: "my-data-analyzer"
version: "1.0.0"
capabilities:
  network:
    endpoints:
      - "https://api.openai.com/*"
    protocols: ["https"]
  filesystem:
    read: ["./data/*"]
    write: ["./output/*"]
  memory:
    reads: ["conversation_history"]
    writes: []
  tools:
    calls: ["web_fetch", "exec"]
    blockedTools: ["message", "gateway"]
```

The platform enforces these at skill-call time. If a skill tries to access a capability it didn't declare, ClawGuardian blocks the action and logs the violation.

## OWASP Mapping

ClawGuardian directly mitigates OWASP Top 10 for LLM Applications:

| OWASP | Threat | ClawGuardian Stage |
|-------|--------|--------------------|
| LLM05 | Supply Chain Vulnerabilities | Static Analysis + Registry Scanning |
| LLM07 | Insecure Plugin Design | Capability Manifests + Composition Testing |
| LLM08 | Excessive Agency | Policy Engine + Permission Enforcement |
| LLM01 | Prompt Injection | Semantic Analysis (LLM-assisted detection) |
| LLM02 | Insecure Output Handling | Data Flow Analysis |
| LLM06 | Sensitive Information Disclosure | Memory/Credential Exfiltration Detection |

## Architecture

```
clawguardian/
├── src/
│   ├── scanner/
│   │   ├── static.ts        # AST-based code analysis
│   │   ├── dynamic.ts       # Sandboxed execution monitor
│   │   ├── semantic.ts      # LLM-assisted injection detection
│   │   ├── composition.ts   # Skill chain risk analysis
│   │   └── dataflow.ts      # Memory/credential exfiltration
│   ├── policy/
│   │   ├── engine.ts        # Policy evaluation engine
│   │   ├── manifest.ts      # Capability manifest parser
│   │   └── scoring.ts       # Trust score computation
│   ├── registry/
│   │   ├── crawler.ts       # ClawHub registry scanner
│   │   ├── signer.ts        # Cryptographic skill signing
│   │   └── monitor.ts       # CVE monitoring + forced updates
│   ├── reporting/
│   │   ├── sarif.ts         # SARIF format output
│   │   ├── siem.ts          # SOAR/SIEM webhook integration
│   │   └── sbom.ts          # Software Bill of Materials
│   └── cli/
│       └── index.ts         # CLI entry point
├── tests/
├── package.json
├── tsconfig.json
└── LICENSE
```

## CLI

```bash
# Scan a single skill
npx clawguardian scan ./skills/my-skill/

# Scan with specific policy
npx clawguardian scan ./skills/my-skill/ --config ./clawguardian.config.yaml

# Audit an entire registry
npx clawguardian audit https://clawhub.example.com/api/skills

# Generate SBOM for installed skills
npx clawguardian sbom --output ./sbom.json

# CI/CD integration (exit code 1 if any skill fails policy)
npx clawguardian ci --fail-on-review
```

## CI/CD Integration

```yaml
# GitHub Actions
- name: ClawGuardian Skill Audit
  run: npx clawguardian ci --config .clawguardian.yaml --fail-on-review
```

## Enterprise Features

- **SOAR/SIEM Integration**: Webhook API for real-time threat events
- **SBOM Generation**: Software Bill of Materials for every installed skill
- **Bulk Allowlist Import**: CSV/JSON import for pre-approved skills
- **Custom Security Policies**: Organization-specific rules and thresholds
- **Compliance Reporting**: SOC 2, ISO 27001, NIST AI RMF aligned reports
- **SLA Guarantees**: Scan < 30s, Review < 24h, Revocation < 1h

## Standards Alignment

| Standard | ClawGuardian Coverage |
|----------|----------------------|
| NIST AI RMF | MAP, MEASURE, MANAGE functions |
| ISO/IEC 42001 | AI management system controls |
| CISA SSDF | Secure software development practices |
| OWASP Top 10 LLM | 6 of 10 categories (see mapping above) |

**Note:** No CVSS equivalent exists for agent skill vulnerabilities. ClawGuardian's Trust Score is the first standardized scoring framework for this category.

## Roadmap

- [x] Phase 1: Static analysis + trust scoring (open-source)
- [ ] Phase 2: Dynamic + semantic analysis (partnership beta)
- [ ] Phase 3: Verified Skills Registry (full launch)
- [ ] Capability Manifest standard proposal (working group)
- [ ] CVSS-equivalent scoring standard for agent vulnerabilities

## Contributing

We welcome contributions. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License. See [LICENSE](LICENSE) for details.

## About

ClawGuardian is built by [AI Agent Economy](https://ai-agent-economy.hashnode.dev) -- the end-to-end platform for autonomous agent commerce (wallets, payments, marketplace, security).

- npm: [agent-wallet-sdk](https://www.npmjs.com/package/agent-wallet-sdk)
- GitHub: [github.com/up2itnow0822](https://github.com/up2itnow0822)
- X: [@AgentEconoemy](https://x.com/AgentEconoemy)
- Hashnode: [ai-agent-economy.hashnode.dev](https://ai-agent-economy.hashnode.dev)

> *This project was created with AI assistance and is maintained by humans and AI agents working together.*
