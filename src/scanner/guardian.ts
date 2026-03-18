/**
 * ClawGuardian - Main scanner orchestrator
 *
 * Coordinates the 5-stage scanning pipeline and produces
 * unified trust scores and recommendations.
 */

import { readFileSync, existsSync } from 'fs';
import { join, basename } from 'path';
import { parse as parseYaml } from 'yaml';
import { StaticAnalyzer } from './static';
import { PolicyEngine } from '../policy/engine';
import { TrustScorer } from '../policy/scoring';
import { ManifestParser } from '../policy/manifest';
import type {
  ScanConfig,
  ScanResult,
  PolicyConfig,
  StageResult,
  Threat,
  SkillMetadata,
  ScanStage,
  Recommendation,
} from '../types';

const DEFAULT_STAGES: ScanStage[] = ['static'];

export class ClawGuardian {
  private config: ScanConfig;
  private policy: PolicyEngine;
  private scorer: TrustScorer;
  private staticAnalyzer: StaticAnalyzer;

  constructor(config: Partial<ScanConfig> = {}) {
    this.config = {
      stages: config.stages || DEFAULT_STAGES,
      timeout: config.timeout || 30000,
      concurrency: config.concurrency || 5,
      outputFormat: config.outputFormat || 'json',
      ...config,
    };

    let policyConfig: PolicyConfig | undefined;
    if (config.policy && existsSync(config.policy)) {
      const raw = readFileSync(config.policy, 'utf-8');
      policyConfig = parseYaml(raw) as PolicyConfig;
    }

    this.policy = new PolicyEngine(policyConfig);
    this.scorer = new TrustScorer();
    this.staticAnalyzer = new StaticAnalyzer();
  }

  /**
   * Scan a skill directory and return a full security assessment.
   */
  async scan(skillPath: string): Promise<ScanResult> {
    const startTime = Date.now();
    const metadata = this.extractMetadata(skillPath);
    const manifest = ManifestParser.parse(skillPath);
    const stages: StageResult[] = [];
    const allThreats: Threat[] = [];

    // Stage 1: Static Analysis
    if (this.config.stages.includes('static')) {
      const staticResult = await this.runStage('static', async () => {
        return this.staticAnalyzer.analyze(skillPath, metadata);
      });
      stages.push(staticResult);
      allThreats.push(...staticResult.threats);
    }

    // Stage 2: Dynamic Analysis (sandboxed execution)
    if (this.config.stages.includes('dynamic')) {
      const dynamicResult = await this.runStage('dynamic', async () => {
        // Phase 2: Sandboxed execution monitoring
        // Requires partnership integration for behavioral sandbox
        return { threats: [], score: 1.0 };
      });
      stages.push(dynamicResult);
      allThreats.push(...dynamicResult.threats);
    }

    // Stage 3: Semantic Analysis (LLM-assisted)
    if (this.config.stages.includes('semantic')) {
      const semanticResult = await this.runStage('semantic', async () => {
        // Phase 2: LLM-assisted injection detection
        // Classifies skill outputs for prompt injection patterns
        return { threats: [], score: 1.0 };
      });
      stages.push(semanticResult);
      allThreats.push(...semanticResult.threats);
    }

    // Stage 4: Composition Testing
    if (this.config.stages.includes('composition')) {
      const compositionResult = await this.runStage('composition', async () => {
        // Phase 2: Skill dependency graph + interaction testing
        return { threats: [], score: 1.0 };
      });
      stages.push(compositionResult);
      allThreats.push(...compositionResult.threats);
    }

    // Stage 5: Memory/Data Flow Analysis
    if (this.config.stages.includes('dataflow')) {
      const dataflowResult = await this.runStage('dataflow', async () => {
        // Phase 2: Credential exfiltration + side-channel detection
        return { threats: [], score: 1.0 };
      });
      stages.push(dataflowResult);
      allThreats.push(...dataflowResult.threats);
    }

    // Compute trust score across all stages
    const trustScore = this.scorer.compute(stages, metadata);

    // Determine recommendation based on policy
    const recommendation = this.policy.recommend(trustScore, allThreats);

    return {
      skillPath,
      skillName: metadata.name,
      version: metadata.version,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      trustScore,
      threats: allThreats,
      recommendation,
      manifest: manifest || undefined,
      metadata,
      stages,
    };
  }

  /**
   * Scan an entire skill registry.
   */
  async scanRegistry(
    registryUrl: string,
    options: { concurrency?: number; outputFormat?: string; reportDir?: string } = {}
  ) {
    const startTime = Date.now();
    // Phase 1: Registry crawling + batch scanning
    // This will be implemented with the registry crawler module
    return {
      total: 0,
      safe: 0,
      review: 0,
      blocked: 0,
      results: [],
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
    };
  }

  private async runStage(
    stage: ScanStage,
    fn: () => Promise<{ threats: Threat[]; score: number }>
  ): Promise<StageResult> {
    const start = Date.now();
    try {
      const result = await Promise.race([
        fn(),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`Stage ${stage} timed out`)), this.config.timeout)
        ),
      ]);
      return {
        stage,
        passed: result.score >= (this.policy.getThreshold('review') || 0.7),
        duration: Date.now() - start,
        threats: result.threats,
        score: result.score,
      };
    } catch (error) {
      return {
        stage,
        passed: false,
        duration: Date.now() - start,
        threats: [{
          id: `${stage}-error`,
          stage,
          severity: 'high',
          category: 'scan-error',
          description: `Stage ${stage} failed: ${(error as Error).message}`,
        }],
        score: 0,
      };
    }
  }

  private extractMetadata(skillPath: string): SkillMetadata {
    const pkgPath = join(skillPath, 'package.json');
    const skillMdPath = join(skillPath, 'SKILL.md');
    let name = basename(skillPath);
    let version = '0.0.0';
    let author: string | undefined;
    let description: string | undefined;
    let dependencies: Record<string, string> = {};

    if (existsSync(pkgPath)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
        name = pkg.name || name;
        version = pkg.version || version;
        author = pkg.author;
        description = pkg.description;
        dependencies = pkg.dependencies || {};
      } catch {
        // Invalid package.json -- will be flagged by static analysis
      }
    }

    const files = this.listFiles(skillPath);
    const totalLines = files.reduce((sum, f) => {
      try {
        return sum + readFileSync(f, 'utf-8').split('\n').length;
      } catch {
        return sum;
      }
    }, 0);

    return {
      name,
      version,
      author,
      description,
      dependencies,
      files,
      totalLines,
      hasTests: files.some(f => f.includes('test') || f.includes('spec')),
      hasManifest: existsSync(join(skillPath, 'skill-manifest.yaml')),
      hasLockfile: existsSync(join(skillPath, 'package-lock.json')) ||
                   existsSync(join(skillPath, 'yarn.lock')) ||
                   existsSync(join(skillPath, 'pnpm-lock.yaml')),
    };
  }

  private listFiles(dir: string, depth = 0): string[] {
    if (depth > 5) return [];
    const { readdirSync, statSync } = require('fs');
    const results: string[] = [];
    try {
      for (const entry of readdirSync(dir)) {
        if (entry === 'node_modules' || entry === '.git' || entry === 'dist') continue;
        const full = join(dir, entry);
        try {
          const stat = statSync(full);
          if (stat.isDirectory()) {
            results.push(...this.listFiles(full, depth + 1));
          } else {
            results.push(full);
          }
        } catch {
          // Skip inaccessible files
        }
      }
    } catch {
      // Skip inaccessible directories
    }
    return results;
  }
}
