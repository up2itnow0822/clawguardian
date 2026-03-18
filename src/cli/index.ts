#!/usr/bin/env node
/**
 * ClawGuardian CLI - Scan skills and audit registries from the command line
 */

import { ClawGuardian } from '../scanner/guardian';
import { SarifReporter } from '../reporting/sarif';
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { join } from 'path';

const RESET = '\x1b[0m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const BOLD = '\x1b[1m';

function printBanner() {
  console.log(`
${CYAN}╔══════════════════════════════════════════════════╗
║          ClawGuardian v0.1.0                     ║
║          AI Agent Skill Security Scanner         ║
╚══════════════════════════════════════════════════╝${RESET}
`);
}

function printResult(result: Awaited<ReturnType<ClawGuardian['scan']>>) {
  const color = result.recommendation === 'safe' ? GREEN
    : result.recommendation === 'review' ? YELLOW
    : RED;

  console.log(`${BOLD}Skill:${RESET}          ${result.skillName} v${result.version}`);
  console.log(`${BOLD}Trust Score:${RESET}    ${color}${(result.trustScore.overall * 100).toFixed(1)}%${RESET}`);
  console.log(`${BOLD}Recommendation:${RESET} ${color}${result.recommendation.toUpperCase()}${RESET}`);
  console.log(`${BOLD}Threats:${RESET}        ${result.threats.length} found`);
  console.log(`${BOLD}Duration:${RESET}       ${result.duration}ms`);
  console.log();

  if (result.threats.length > 0) {
    console.log(`${BOLD}Threats:${RESET}`);
    for (const threat of result.threats) {
      const sev = threat.severity === 'critical' ? RED
        : threat.severity === 'high' ? RED
        : threat.severity === 'medium' ? YELLOW
        : GREEN;
      const loc = threat.file ? ` (${threat.file}${threat.line ? `:${threat.line}` : ''})` : '';
      console.log(`  ${sev}[${threat.severity.toUpperCase()}]${RESET} ${threat.description}${loc}`);
    }
    console.log();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    printBanner();
    console.log(`Usage:
  clawguardian scan <path>              Scan a skill directory
  clawguardian audit <registry-url>     Audit an entire registry
  clawguardian sbom --output <file>     Generate SBOM for installed skills
  clawguardian ci                       CI mode (exit 1 on review/block)

Options:
  --config <path>    Policy config file (clawguardian.config.yaml)
  --format <format>  Output format: json, sarif, text (default: text)
  --output <path>    Write report to file
  --fail-on-review   In CI mode, fail on review (not just block)
  --help             Show this help
`);
    process.exit(0);
  }

  const configIdx = args.indexOf('--config');
  const configPath = configIdx >= 0 ? args[configIdx + 1] : undefined;
  const formatIdx = args.indexOf('--format');
  const format = formatIdx >= 0 ? args[formatIdx + 1] : 'text';
  const outputIdx = args.indexOf('--output');
  const outputPath = outputIdx >= 0 ? args[outputIdx + 1] : undefined;
  const failOnReview = args.includes('--fail-on-review');

  const guardian = new ClawGuardian({
    stages: ['static'],
    policy: configPath,
    outputFormat: format as 'json' | 'sarif' | 'text',
  });

  if (command === 'scan') {
    const skillPath = args[1];
    if (!skillPath) {
      console.error('Error: skill path required. Usage: clawguardian scan <path>');
      process.exit(1);
    }

    printBanner();
    console.log(`Scanning: ${skillPath}\n`);

    const result = await guardian.scan(skillPath);
    printResult(result);

    if (format === 'sarif' || outputPath?.endsWith('.sarif')) {
      const sarif = SarifReporter.generate(result);
      const sarifJson = JSON.stringify(sarif, null, 2);
      if (outputPath) {
        writeFileSync(outputPath, sarifJson);
        console.log(`SARIF report written to: ${outputPath}`);
      } else {
        console.log(sarifJson);
      }
    } else if (format === 'json') {
      const json = JSON.stringify(result, null, 2);
      if (outputPath) {
        writeFileSync(outputPath, json);
        console.log(`JSON report written to: ${outputPath}`);
      } else {
        console.log(json);
      }
    }
  } else if (command === 'ci') {
    const skillPath = args[1] || '.';
    const result = await guardian.scan(skillPath);

    printBanner();
    printResult(result);

    if (result.recommendation === 'block') {
      console.error(`${RED}CI FAILED: Skill blocked by security policy${RESET}`);
      process.exit(1);
    }
    if (failOnReview && result.recommendation === 'review') {
      console.error(`${YELLOW}CI FAILED: Skill requires manual security review${RESET}`);
      process.exit(1);
    }

    console.log(`${GREEN}CI PASSED${RESET}`);
    process.exit(0);
  } else {
    console.error(`Unknown command: ${command}. Use --help for usage.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal:', err.message || err);
  process.exit(1);
});
