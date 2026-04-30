import type { AegisToolContext, AegisToolEntry } from '../tool-types';
import { buildSDKTool } from '../tool-types';
import { projectsTools } from './projects';
import { securityTools } from './security';
import { intelligenceTools } from './intelligence';
import { policyTools } from './policy';
import { fixTools } from './fix';

export const ALL_AEGIS_TOOLS: AegisToolEntry[] = [
  ...projectsTools,
  ...securityTools,
  ...intelligenceTools,
  ...policyTools,
  ...fixTools,
];

export function buildToolSet(ctx: AegisToolContext) {
  return Object.fromEntries(
    ALL_AEGIS_TOOLS.map((entry) => [entry.name, buildSDKTool(entry, ctx)]),
  );
}
