/**
 * Policy Engine - Evaluates scan results against configurable security policies
 */

import type { PolicyConfig, Threat, TrustScore, Recommendation } from '../types';

const DEFAULT_THRESHOLDS = {
  block: 0.3,
  review: 0.7,
  safe: 0.7,
};

export class PolicyEngine {
  private config: PolicyConfig | undefined;

  constructor(config?: PolicyConfig) {
    this.config = config;
  }

  getThreshold(level: 'block' | 'review' | 'safe'): number {
    return this.config?.clawguardian?.trustThresholds?.[level] ?? DEFAULT_THRESHOLDS[level];
  }

  recommend(trustScore: TrustScore, threats: Threat[]): Recommendation {
    const hasCritical = threats.some(t => t.severity === 'critical');
    if (hasCritical) return 'block';

    const blockThreshold = this.getThreshold('block');
    const reviewThreshold = this.getThreshold('review');

    if (trustScore.overall < blockThreshold) return 'block';
    if (trustScore.overall < reviewThreshold) return 'review';
    return 'safe';
  }
}
