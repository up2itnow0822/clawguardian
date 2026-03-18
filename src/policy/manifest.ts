/**
 * Manifest Parser - Reads and validates skill capability manifests
 */

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { parse as parseYaml } from 'yaml';
import type { CapabilityManifest } from '../types';

export class ManifestParser {
  static parse(skillPath: string): CapabilityManifest | null {
    const manifestPath = join(skillPath, 'skill-manifest.yaml');
    if (!existsSync(manifestPath)) return null;

    try {
      const raw = readFileSync(manifestPath, 'utf-8');
      const parsed = parseYaml(raw) as CapabilityManifest;

      if (!parsed.name || !parsed.version) {
        throw new Error('Manifest missing required fields: name, version');
      }

      return {
        name: parsed.name,
        version: parsed.version,
        capabilities: {
          network: parsed.capabilities?.network || { endpoints: [], protocols: [] },
          filesystem: parsed.capabilities?.filesystem || { read: [], write: [] },
          memory: parsed.capabilities?.memory || { reads: [], writes: [] },
          tools: parsed.capabilities?.tools || { calls: [], blockedTools: [] },
        },
      };
    } catch {
      return null;
    }
  }
}
