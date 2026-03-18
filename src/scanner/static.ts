/**
 * Static Analysis - Stage 1
 *
 * AST-based code analysis, dependency audit, permission scope,
 * and known malware signature detection.
 */

import { readFileSync } from 'fs';
import type { Threat, SkillMetadata } from '../types';

// Known malicious patterns (expanded from Bitdefender ClawHub research)
const MALICIOUS_PATTERNS = [
  { pattern: /eval\s*\(/, category: 'code-injection', severity: 'high' as const, description: 'Dynamic code execution via eval()' },
  { pattern: /Function\s*\(/, category: 'code-injection', severity: 'high' as const, description: 'Dynamic function construction' },
  { pattern: /child_process/, category: 'system-access', severity: 'critical' as const, description: 'Child process spawning capability' },
  { pattern: /process\.env/, category: 'credential-access', severity: 'medium' as const, description: 'Environment variable access (potential credential read)' },
  { pattern: /\.ssh\//, category: 'credential-access', severity: 'critical' as const, description: 'SSH key directory access' },
  { pattern: /\/etc\/passwd/, category: 'system-access', severity: 'critical' as const, description: 'System password file access' },
  { pattern: /keychain|keyring|wallet.*key|private.*key|secret.*key/i, category: 'credential-access', severity: 'high' as const, description: 'Potential credential/key access pattern' },
  { pattern: /base64.*decode.*exec|exec.*base64.*decode/i, category: 'obfuscation', severity: 'critical' as const, description: 'Base64-encoded code execution (common malware pattern)' },
  { pattern: /require\s*\(\s*['"]https?:\/\//i, category: 'remote-code', severity: 'critical' as const, description: 'Remote code loading via require()' },
  { pattern: /fetch\s*\(\s*['"]https?:\/\/[^'"]*\.(onion|bit|i2p)/i, category: 'darknet', severity: 'critical' as const, description: 'Darknet endpoint communication' },
  { pattern: /XMLHttpRequest|ActiveXObject/i, category: 'network', severity: 'medium' as const, description: 'Legacy network request API usage' },
  { pattern: /document\.cookie|localStorage|sessionStorage/i, category: 'data-exfiltration', severity: 'high' as const, description: 'Browser storage access (potential data theft)' },
  { pattern: /crypto\.createCipher|crypto\.createDecipher/i, category: 'encryption', severity: 'medium' as const, description: 'Deprecated crypto API usage' },
  { pattern: /dns\.resolve|dgram\.createSocket/i, category: 'dns-tunneling', severity: 'high' as const, description: 'DNS resolution or UDP socket (potential DNS tunneling)' },
  { pattern: /net\.createServer|http\.createServer/i, category: 'server', severity: 'high' as const, description: 'Server creation (potential reverse shell or C2)' },
  { pattern: /AMOS|Atomic.*Stealer|infostealer/i, category: 'known-malware', severity: 'critical' as const, description: 'Known malware signature match (AMOS infostealer)' },
];

// Known vulnerable or malicious npm packages
const BLOCKLISTED_DEPS = new Set([
  'event-stream',           // Compromised in 2018
  'flatmap-stream',         // Malicious dependency
  'ua-parser-js',           // Compromised versions
  'coa',                    // Compromised
  'rc',                     // Compromised versions
  'colors',                 // Sabotaged by maintainer
  'faker',                  // Sabotaged by maintainer
  'node-ipc',              // Protestware
]);

export class StaticAnalyzer {
  /**
   * Run static analysis on a skill directory.
   */
  async analyze(skillPath: string, metadata: SkillMetadata): Promise<{ threats: Threat[]; score: number }> {
    const threats: Threat[] = [];
    let deductions = 0;

    // 1. Check for blocklisted dependencies
    for (const dep of Object.keys(metadata.dependencies)) {
      if (BLOCKLISTED_DEPS.has(dep)) {
        threats.push({
          id: `dep-blocklist-${dep}`,
          stage: 'static',
          severity: 'critical',
          category: 'supply-chain',
          description: `Blocklisted dependency detected: ${dep} (known compromised/malicious package)`,
          owaspMapping: 'LLM05 - Supply Chain Vulnerabilities',
          remediation: `Remove ${dep} and find a secure alternative`,
        });
        deductions += 0.3;
      }
    }

    // 2. Check for missing security indicators
    if (!metadata.hasLockfile) {
      threats.push({
        id: 'no-lockfile',
        stage: 'static',
        severity: 'medium',
        category: 'supply-chain',
        description: 'No lockfile found (package-lock.json, yarn.lock, or pnpm-lock.yaml). Dependencies are not pinned.',
        owaspMapping: 'LLM05 - Supply Chain Vulnerabilities',
        remediation: 'Run npm install to generate a lockfile and commit it',
      });
      deductions += 0.1;
    }

    if (!metadata.hasTests) {
      threats.push({
        id: 'no-tests',
        stage: 'static',
        severity: 'low',
        category: 'quality',
        description: 'No test files detected. Skills without tests are harder to verify for correctness.',
        remediation: 'Add test files to validate skill behavior',
      });
      deductions += 0.05;
    }

    if (!metadata.hasManifest) {
      threats.push({
        id: 'no-manifest',
        stage: 'static',
        severity: 'medium',
        category: 'policy',
        description: 'No capability manifest (skill-manifest.yaml) found. Cannot enforce permission boundaries.',
        owaspMapping: 'LLM08 - Excessive Agency',
        remediation: 'Add a skill-manifest.yaml declaring required capabilities',
      });
      deductions += 0.15;
    }

    // 3. Scan source files for malicious patterns
    for (const file of metadata.files) {
      if (!file.match(/\.(ts|js|mjs|cjs|py|sh|yaml|yml|json)$/)) continue;

      let content: string;
      try {
        content = readFileSync(file, 'utf-8');
      } catch {
        continue;
      }

      const lines = content.split('\n');

      for (const pattern of MALICIOUS_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
          if (pattern.pattern.test(lines[i])) {
            threats.push({
              id: `pattern-${pattern.category}-${file}-${i + 1}`,
              stage: 'static',
              severity: pattern.severity,
              category: pattern.category,
              description: pattern.description,
              file: file.replace(skillPath, '.'),
              line: i + 1,
              evidence: lines[i].trim().substring(0, 120),
              remediation: `Review line ${i + 1} in ${file} for security implications`,
            });

            // Deductions based on severity
            switch (pattern.severity) {
              case 'critical': deductions += 0.25; break;
              case 'high': deductions += 0.15; break;
              case 'medium': deductions += 0.08; break;
              case 'low': deductions += 0.03; break;
            }
          }
        }
      }

      // 4. Check for excessive dependency count (>20 deps is suspicious for a skill)
      if (Object.keys(metadata.dependencies).length > 20) {
        threats.push({
          id: 'excessive-deps',
          stage: 'static',
          severity: 'medium',
          category: 'supply-chain',
          description: `Excessive dependencies (${Object.keys(metadata.dependencies).length}). Large dependency trees increase attack surface.`,
          owaspMapping: 'LLM05 - Supply Chain Vulnerabilities',
          remediation: 'Audit and reduce dependencies to minimize supply chain risk',
        });
        deductions += 0.1;
      }

      // 5. Check for obfuscated code (high entropy strings)
      const longStrings = content.match(/['"][^'"]{100,}['"]/g) || [];
      if (longStrings.length > 3) {
        threats.push({
          id: `obfuscation-${file}`,
          stage: 'static',
          severity: 'high',
          category: 'obfuscation',
          description: `${longStrings.length} unusually long string literals detected. May indicate obfuscated code or embedded payloads.`,
          file: file.replace(skillPath, '.'),
          remediation: 'Review long string literals for encoded malicious content',
        });
        deductions += 0.2;
      }
    }

    const score = Math.max(0, Math.min(1, 1.0 - deductions));
    return { threats, score };
  }
}
