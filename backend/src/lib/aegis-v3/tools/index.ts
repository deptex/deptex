import type { AegisToolContext, AegisToolEntry } from '../tool-types';
import { buildSDKTool } from '../tool-types';

export const ALL_AEGIS_TOOLS: AegisToolEntry[] = [];

export function buildToolSet(ctx: AegisToolContext) {
  return Object.fromEntries(
    ALL_AEGIS_TOOLS.map((entry) => [entry.name, buildSDKTool(entry, ctx)]),
  );
}
