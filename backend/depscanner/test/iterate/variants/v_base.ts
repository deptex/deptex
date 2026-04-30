/**
 * Control variant — re-exports the current production prompt-builder.
 * Tournament numbers measured against this baseline.
 */

import { buildGenerationPrompt, getPromptVersion } from '../../../src/rule-generator/prompt-builder';

export const NAME = 'v_base';
export const VERSION = `base-${getPromptVersion()}`;

export { buildGenerationPrompt };
