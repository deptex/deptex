// Per-model pre-flight estimate in cents — the most a typical single Aegis
// turn at this model will cost. Used by the /can-charge gate to refuse
// stream-start when the org's balance won't even cover one turn.
//
// Estimates assume ~2k input + 1k output tokens at the model's published
// price, doubled to match the 2x markup, then rounded to a safe ceiling.
// When the model isn't listed, DEFAULT_AEGIS_ESTIMATE_CENTS applies.
//
// Fresh-org rule: orgs with no successful topup AND no auto_recharge_topup
// in their ledger are forced to claude-haiku-4-5-20251001 regardless of
// org/user model preference. UI shows an upgrade hint.

export const AEGIS_TURN_ESTIMATE_CENTS: Record<string, number> = {
  // Haiku family — cheap; default for fresh orgs
  'claude-haiku-4-5-20251001': 50,
  'gemini-3-flash':            50,
  'gpt-5-nano':                50,
  'gpt-5.4-nano':              50,
  // Mid-tier
  'claude-sonnet-4-6':         200,
  'gemini-3.1-pro':            200,
  'gpt-5.4':                   200,
  // Premium
  'gpt-5.5':                   400,
  'claude-opus-4-7':           800,
  'gpt-5.5-pro':               1500,
};

export const DEFAULT_AEGIS_ESTIMATE_CENTS = 200;

export const FRESH_ORG_DEFAULT_MODEL_ID = 'claude-haiku-4-5-20251001';

export function getAegisTurnEstimateCents(modelId: string | undefined): number {
  if (!modelId) return DEFAULT_AEGIS_ESTIMATE_CENTS;
  return AEGIS_TURN_ESTIMATE_CENTS[modelId] ?? DEFAULT_AEGIS_ESTIMATE_CENTS;
}
