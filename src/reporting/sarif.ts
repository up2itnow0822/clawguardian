/**
 * SARIF Reporter - Generates SARIF 2.1.0 format reports for CI/CD integration
 */

import type { ScanResult, Threat } from '../types';

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

interface SarifRun {
  tool: { driver: { name: string; version: string; rules: SarifRule[] } };
  results: SarifResult[];
}

interface SarifRule {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  defaultConfiguration: { level: string };
}

interface SarifResult {
  ruleId: string;
  level: string;
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region?: { startLine: number };
    };
  }>;
}

export class SarifReporter {
  static generate(result: ScanResult): SarifReport {
    const rules: SarifRule[] = [];
    const results: SarifResult[] = [];
    const seenRules = new Set<string>();

    for (const threat of result.threats) {
      const ruleId = `CG-${threat.category.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`;

      if (!seenRules.has(ruleId)) {
        seenRules.add(ruleId);
        rules.push({
          id: ruleId,
          shortDescription: { text: threat.category },
          fullDescription: { text: threat.description },
          defaultConfiguration: { level: mapSeverity(threat.severity) },
        });
      }

      const sarifResult: SarifResult = {
        ruleId,
        level: mapSeverity(threat.severity),
        message: { text: threat.description },
      };

      if (threat.file) {
        sarifResult.locations = [{
          physicalLocation: {
            artifactLocation: { uri: threat.file },
            ...(threat.line ? { region: { startLine: threat.line } } : {}),
          },
        }];
      }

      results.push(sarifResult);
    }

    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'ClawGuardian',
            version: '0.1.0',
            rules,
          },
        },
        results,
      }],
    };
  }
}

function mapSeverity(severity: string): string {
  switch (severity) {
    case 'critical': return 'error';
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
    case 'info': return 'note';
    default: return 'warning';
  }
}
