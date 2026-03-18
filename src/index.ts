/**
 * ClawGuardian - Open-source security framework for AI agent skill ecosystems
 *
 * Static analysis, behavioral monitoring, trust scoring, and composition
 * risk detection for OpenClaw skills and plugins.
 *
 * @packageDocumentation
 */

export { ClawGuardian } from './scanner/guardian';
export { StaticAnalyzer } from './scanner/static';
export { PolicyEngine } from './policy/engine';
export { ManifestParser } from './policy/manifest';
export { TrustScorer } from './policy/scoring';
export { SarifReporter } from './reporting/sarif';

export type {
  ScanResult,
  Threat,
  ThreatSeverity,
  TrustScore,
  ScanConfig,
  PolicyConfig,
  CapabilityManifest,
  SkillMetadata,
  CompositionRisk,
} from './types';
