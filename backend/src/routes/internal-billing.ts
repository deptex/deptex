import express from 'express';
import { z } from 'zod';
import { supabase } from '../lib/supabase';
import { recordMeterEvent, canCharge } from '../lib/billing/ledger';
import { chargedCentsForWorker } from '../lib/billing/pricing';
import { chargedCentsForAi } from '../lib/ai/pricing';
import { requireInternalKey } from '../middleware/internal-key';
import { captureBillingError } from '../lib/observability/capture';

const router = express.Router();

router.use(requireInternalKey);

// Job-binding (fail-closed): every HTTP meter-event caller binds its charge to a job row —
// depscanner sends scan_job, fix-worker sends fix_task. We look that row up and derive its
// real org_id; if the body's organization_id disagrees, or the attribution can't be bound to
// a real resource, we REJECT. A leaked INTERNAL_API_KEY therefore can't drain an arbitrary
// org — it can only charge orgs with legitimate active work it can actually name.
//
// In-process callers (aegis-v3, EPD, rule generation) call recordMeterEvent directly with a
// trusted org_id and never reach this HTTP route, so they need no mapping here.
//
// Returns:
//   { ok: true }                  — attribution resolved and org matches
//   { ok: false, reason: string } — missing / unbindable / mismatched (caller returns 403)
async function verifyAttribution(
  bodyOrgId: string,
  attribution: { resource_type?: string; resource_id?: string } | undefined,
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const resourceType = attribution?.resource_type;
  const resourceId = attribution?.resource_id;
  if (!resourceType || !resourceId) {
    return { ok: false, reason: 'attribution required (resource_type + resource_id)' };
  }

  // Each bindable resource type → the table that owns organization_id. Types with no HTTP
  // caller (rule_generation / epd_scoring) aren't listed, so they fall through to reject.
  const tableByType: Record<string, string> = {
    aegis_chat: 'aegis_chat_threads',
    scan_job: 'scan_jobs',
    fix_task: 'project_security_fixes',
  };
  const table = tableByType[resourceType];
  if (!table) {
    return { ok: false, reason: `unbindable resource_type: ${resourceType}` };
  }

  const { data } = await supabase
    .from(table)
    .select('organization_id')
    .eq('id', resourceId)
    .maybeSingle();
  const actualOrgId = (data as any)?.organization_id ?? null;
  if (!actualOrgId) {
    return { ok: false, reason: `${resourceType} ${resourceId} not found` };
  }
  if (actualOrgId !== bodyOrgId) {
    return {
      ok: false,
      reason: `attribution org mismatch: body=${bodyOrgId} ${resourceType}.org=${actualOrgId}`,
    };
  }
  return { ok: true };
}

const MAX_TOKEN_QUANTITY = 5_000_000;
const MAX_DURATION_SECONDS = 24 * 60 * 60;

const meterEventSchema = z
  .object({
    organization_id: z.string().uuid(),
    project_id: z.string().uuid().optional(),
    event_type: z.enum(['ai_tokens', 'worker_minutes']),
    provider: z.enum(['openai', 'anthropic', 'google', 'deepinfra', 'fly']),
    feature: z.string().min(1).max(100),
    quantity: z.number().positive().finite(),
    output_quantity: z.number().positive().finite().optional(),
    unit: z.enum(['input_tokens', 'output_tokens', 'seconds', 'mixed_tokens']),
    model_id: z.string().optional(),
    machine_size: z.string().optional(),
    attribution: z
      .object({
        user_id: z.string().uuid().optional(),
        resource_type: z
          .enum(['aegis_chat', 'scan_job', 'fix_task', 'rule_generation', 'epd_scoring'])
          .optional(),
        resource_id: z.string().uuid().optional(),
      })
      .optional(),
    idempotency_key: z.string().min(1).max(200),
  })
  .superRefine((data, ctx) => {
    if (data.event_type === 'ai_tokens' && !['input_tokens', 'output_tokens', 'mixed_tokens'].includes(data.unit)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'ai_tokens requires unit in input_tokens|output_tokens|mixed_tokens',
      });
    }
    if (data.event_type === 'worker_minutes' && data.unit !== 'seconds') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: 'worker_minutes requires unit=seconds',
      });
    }
    if (data.event_type === 'ai_tokens' && data.quantity > MAX_TOKEN_QUANTITY) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `quantity exceeds ceiling ${MAX_TOKEN_QUANTITY}`,
      });
    }
    if (data.event_type === 'worker_minutes' && data.quantity > MAX_DURATION_SECONDS) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `quantity exceeds ceiling ${MAX_DURATION_SECONDS}s`,
      });
    }
  });

router.post('/meter-event', async (req, res) => {
  const parsed = meterEventSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: 'invalid_meter_event',
      details: parsed.error.issues.map((i) => i.message),
    });
  }
  const body = parsed.data;

  // Job-binding check (P0-2 mitigation, fail-closed). org_id MUST resolve from a job row the
  // caller names — body.organization_id can't be trusted on its own because INTERNAL_API_KEY
  // is a single shared secret across all workers. Unbindable/missing attribution → 403.
  const attrResult = await verifyAttribution(body.organization_id, body.attribution);
  if (attrResult.ok === false) {
    console.error('[billing] meter-event attribution rejected', {
      orgId: body.organization_id,
      attribution: body.attribution,
      reason: attrResult.reason,
    });
    return res.status(403).json({ error: 'attribution_mismatch', detail: attrResult.reason });
  }

  let cogCents = 0;
  let chargedCents = 0;
  if (body.event_type === 'ai_tokens') {
    if (!body.model_id) return res.status(400).json({ error: 'model_id required for ai_tokens' });
    const cost = chargedCentsForAi(body.model_id, body.quantity, body.output_quantity ?? 0);
    cogCents = cost.cogCents;
    chargedCents = cost.chargedCents;
  } else {
    if (!body.machine_size) return res.status(400).json({ error: 'machine_size required for worker_minutes' });
    const cost = chargedCentsForWorker(body.machine_size, body.quantity);
    cogCents = cost.cogCents;
    chargedCents = cost.chargedCents;
  }

  try {
    const result = await recordMeterEvent({
      organizationId: body.organization_id,
      projectId: body.project_id,
      eventType: body.event_type,
      provider: body.provider,
      feature: body.feature,
      quantity: body.quantity,
      outputQuantity: body.output_quantity,
      unit: body.unit,
      cogCents,
      chargedCents,
      modelId: body.model_id,
      machineSize: body.machine_size,
      attribution: body.attribution
        ? {
            userId: body.attribution.user_id,
            resourceType: body.attribution.resource_type,
            resourceId: body.attribution.resource_id,
          }
        : undefined,
      idempotencyKey: body.idempotency_key,
    });

    // Post-deduction side-effects (auto-recharge + balance alerts) fire inside
    // recordMeterEvent itself — every caller gets them, not just this HTTP route.

    res.json({
      deducted: result.deducted,
      new_balance_cents: result.newBalanceCents,
      reason: result.reason ?? null,
      cog_cents: cogCents,
      charged_cents: chargedCents,
    });
  } catch (err) {
    console.error('[internal-billing.meter-event] failed', err);
    captureBillingError(err, 'meter_event_failed', { orgId: body.organization_id });
    res.status(500).json({ error: 'meter_event_failed' });
  }
});

const canChargeSchema = z.object({
  organization_id: z.string().uuid(),
  estimated_cents: z.number().int().positive().max(1_000_000),
});

router.post('/can-charge', async (req, res) => {
  const parsed = canChargeSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'invalid_can_charge' });
  try {
    const result = await canCharge(parsed.data.organization_id, parsed.data.estimated_cents);
    res.json({
      allowed: result.allowed,
      balance_cents: result.balanceCents,
      reason: result.reason ?? null,
    });
  } catch (err) {
    console.error('[internal-billing.can-charge] failed', err);
    res.status(500).json({ error: 'can_charge_failed' });
  }
});

export default router;
