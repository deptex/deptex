import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { recommendStrategies } from '../../learning/recommendation-engine';

registerAegisTool(
  'getStrategyRecommendation',
  {
    category: 'intelligence',
    permissionLevel: 'safe',
    requiredRbacPermissions: [],
  },
  tool({
    description: 'Get ranked fix strategy recommendations based on historical outcomes for this organization. Call this before planning any fix to provide context-aware strategy selection.',
    inputSchema: z.object({
      ecosystem: z.string().describe('Package ecosystem (npm, pip, maven, etc.)'),
      vulnerabilityType: z.string().optional().describe('Vulnerability type from CWE (xss, sql-injection, etc.)'),
      isDirect: z.boolean().optional().describe('Whether the dependency is direct'),
      fixType: z.enum(['vulnerability', 'semgrep', 'secret']).describe('Type of fix'),
    }),
    execute: async ({ ecosystem, vulnerabilityType, isDirect, fixType }, { toolCallId }) => {
      try {
        const orgId = (global as any).__aegis_current_org_id;
        if (!orgId) {
          return JSON.stringify({ error: 'Organization context not available' });
        }

        const recommendations = await recommendStrategies(
          orgId,
          ecosystem,
          vulnerabilityType ?? null,
          isDirect ?? true,
          fixType,
        );

        return JSON.stringify({ recommendations });
      } catch (e) {
        return JSON.stringify({ error: `Failed to get recommendations: ${(e as Error).message}` });
      }
    },
  }),
);
