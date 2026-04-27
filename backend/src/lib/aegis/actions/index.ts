/**
 * Aegis Action Registry
 * Defines all available actions that Aegis can perform
 */

export interface ActionDefinition {
  name: string;
  description: string;
  parameters: {
    type: 'object';
    properties: Record<string, {
      type: string;
      description: string;
      required?: boolean;
    }>;
    required?: string[];
  };
}

export interface ActionResult {
  success: boolean;
  data?: any;
  error?: string;
}

export type ActionHandler = (params: any, context: ActionContext) => Promise<ActionResult>;

export interface ActionContext {
  organizationId: string;
  userId: string;
}

// Registry of all actions
export const actionRegistry: Map<string, ActionHandler> = new Map();

// Registry of action definitions for OpenAI function calling
export const actionDefinitions: ActionDefinition[] = [];

/**
 * Register an action
 */
export function registerAction(
  definition: ActionDefinition,
  handler: ActionHandler
): void {
  actionRegistry.set(definition.name, handler);
  actionDefinitions.push(definition);
}

/**
 * Get action handler by name
 */
export function getActionHandler(name: string): ActionHandler | undefined {
  return actionRegistry.get(name);
}

/**
 * Get all action definitions for OpenAI
 */
export function getActionDefinitionsForOpenAI(): any[] {
  return actionDefinitions.map(def => ({
    type: 'function',
    function: {
      name: def.name,
      description: def.description,
      parameters: def.parameters,
    },
  }));
}

