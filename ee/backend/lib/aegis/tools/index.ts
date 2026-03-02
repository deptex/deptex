/**
 * Aegis tool registry - import all tool modules to register them.
 * Each module self-registers its tools when loaded.
 */

import './org-management';
import './project-ops';
import './security-ops';
import './policy';
import './compliance';
import './intelligence';
import './reporting';
import './external';
import './memory';
import './automation';
import './learning';
import './incidents';

export { registerAegisTool, getAllToolMetas, buildToolSet } from './registry';
export type { AegisToolMeta, ToolContext, ToolCategory, PermissionLevel } from './types';
export { TOOL_PROFILES } from './types';
