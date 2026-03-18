/**
 * Trust Scorer - Computes weighted trust scores across scanning stages
 */

import type { StageResult, TrustScore, TrustFactor, SkillMetadata } from '../types';

const STAGE_WEIGHTS: Record<string, number> = {
  static: 0.30,
  dynamic: 0.25,
  semantic: 0.20,
  composition: 0.15,
  dataflow: 0.10,
};

export class TrustScorer {
  compute(stages: StageResult[], metadata: SkillMetadata): TrustScore {
    const factors: TrustFactor[] = [];
    let weightedSum = 0;
    let totalWeight = 0;

    const stageScores: Record<string, number> = {
      static: 1.0,
      dynamic: 1.0,
      semantic: 1.0,
      composition: 1.0,
      dataflow: 1.0,
    };

    for (const stage of stages) {
      const weight = STAGE_WEIGHTS[stage.stage] || 0.1;
      stageScores[stage.stage] = stage.score;
      weightedSum += stage.score * weight;
      totalWeight += weight;

      factors.push({
        name: `${stage.stage}-analysis`,
        score: stage.score,
        weight,
        reason: stage.passed
          ? `${stage.stage} analysis passed (${stage.threats.length} findings)`
          : `${stage.stage} analysis flagged ${stage.threats.length} threat(s)`,
      });
    }

    // Metadata quality bonuses
    if (metadata.hasTests) {
      factors.push({ name: 'has-tests', score: 0.1, weight: 0.05, reason: 'Test files present' });
      weightedSum += 0.1 * 0.05;
      totalWeight += 0.05;
    }

    if (metadata.hasManifest) {
      factors.push({ name: 'has-manifest', score: 0.1, weight: 0.05, reason: 'Capability manifest declared' });
      weightedSum += 0.1 * 0.05;
      totalWeight += 0.05;
    }

    if (metadata.hasLockfile) {
      factors.push({ name: 'has-lockfile', score: 0.05, weight: 0.03, reason: 'Dependencies pinned via lockfile' });
      weightedSum += 0.05 * 0.03;
      totalWeight += 0.03;
    }

    const overall = totalWeight > 0 ? Math.min(1, Math.max(0, weightedSum / totalWeight)) : 0;

    return {
      overall,
      static: stageScores.static,
      dynamic: stageScores.dynamic,
      semantic: stageScores.semantic,
      composition: stageScores.composition,
      dataflow: stageScores.dataflow,
      factors,
    };
  }
}
