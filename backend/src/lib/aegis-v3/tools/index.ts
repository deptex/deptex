import type { AegisToolContext, AegisToolEntry } from '../tool-types';
import { buildSDKTool } from '../tool-types';
import { projectsTools } from './projects';
import { teamsTools } from './teams';
import { membersTools } from './members';
import { rolesTools } from './roles';
import { securityTools } from './security';
import { intelligenceTools } from './intelligence';
import { policyTools } from './policy';
import { issuesTools } from './issues';
import { fixTools } from './fix';

export const ALL_AEGIS_TOOLS: AegisToolEntry[] = [
  ...projectsTools,
  ...teamsTools,
  ...membersTools,
  ...rolesTools,
  ...securityTools,
  ...intelligenceTools,
  ...policyTools,
  ...issuesTools,
  ...fixTools,
];

export function buildToolSet(ctx: AegisToolContext) {
  return Object.fromEntries(
    ALL_AEGIS_TOOLS.map((entry) => [entry.name, buildSDKTool(entry, ctx)]),
  );
}
