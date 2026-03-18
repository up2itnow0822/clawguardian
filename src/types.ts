/**
 * Core types for ClawGuardian scanning and policy framework
 */

export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type ScanStage = 'static' | 'dynamic' | 'semantic' | 'composition' | 'dataflow';

export type Recommendation = 'safe' | 'review' | 'block';

export interface Threat {
  id: string;
  stage: ScanStage;
  severity: ThreatSeverity;
  category: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
  owaspMapping?: string;
  remediation?: string;
}

export interface TrustScore {
  overall: number;        // 0.0 - 1.0
  static: number;
  dynamic: number;
  semantic: number;
  composition: number;
  dataflow: number;
  factors: TrustFactor[];
}

export interface TrustFactor {
  name: string;
  score: number;
  weight: number;
  reason: string;
}

export interface ScanResult {
  skillPath: string;
  skillName: string;
  version: string;
  timestamp: string;
  duration: number;         // milliseconds
  trustScore: TrustScore;
  threats: Threat[];
  recommendation: Recommendation;
  manifest?: CapabilityManifest;
  metadata: SkillMetadata;
  stages: StageResult[];
}

export interface StageResult {
  stage: ScanStage;
  passed: boolean;
  duration: number;
  threats: Threat[];
  score: number;
}

export interface ScanConfig {
  stages: ScanStage[];
  policy?: string;         // path to policy config file
  timeout?: number;        // per-stage timeout in ms
  concurrency?: number;    // for registry scanning
  outputFormat?: 'sarif' | 'json' | 'text';
  reportDir?: string;
}

export interface PolicyConfig {
  clawguardian: {
    scanStages: ScanStage[];
    trustThresholds: {
      block: number;
      review: number;
      safe: number;
    };
    capabilities: {
      maxNetworkEndpoints: number;
      allowedProtocols: string[];
      blockedPatterns: string[];
    };
    composition: {
      maxSkillChainDepth: number;
      blockUnknownInteractions: boolean;
    };
    reporting: {
      format: string;
      outputDir: string;
      siem?: {
        webhook: string;
      };
    };
  };
}

export interface CapabilityManifest {
  name: string;
  version: string;
  capabilities: {
    network?: {
      endpoints: string[];
      protocols: string[];
    };
    filesystem?: {
      read: string[];
      write: string[];
    };
    memory?: {
      reads: string[];
      writes: string[];
    };
    tools?: {
      calls: string[];
      blockedTools: string[];
    };
  };
}

export interface SkillMetadata {
  name: string;
  version: string;
  author?: string;
  description?: string;
  dependencies: Record<string, string>;
  files: string[];
  totalLines: number;
  hasTests: boolean;
  hasManifest: boolean;
  hasLockfile: boolean;
}

export interface CompositionRisk {
  skillA: string;
  skillB: string;
  riskScore: number;
  description: string;
  attackVector: string;
}

export interface RegistryScanResult {
  total: number;
  safe: number;
  review: number;
  blocked: number;
  results: ScanResult[];
  timestamp: string;
  duration: number;
}
