import express from 'express';
import { z } from 'zod';
import { recordMeterEvent, canCharge } from '../lib/billing/ledger';
import { chargedCentsForWorker } from '../lib/billing/pricing';
import { chargedCentsForAi } from '../lib/ai/pricing';
import { checkAndDispatchBalanceAlerts } from '../lib/billing/alerts';
import { maybeAutoRecharge } from '../lib/billing/auto-recharge';

const router = express.Router();

const INTERNAL_API_KEY = process.env.INTERNAL_API_KEY?.trim();

function requireInternalKey(req: express.Request, res: express.Response, next: express.NextFunction) {
  const raw =
    (req.headers['x-internal-api-key'] as string) ||
    (typeof req.headers.authorization === 'string' && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.slice(7)
      : undefined);
  const key = raw?.trim();
  if (!INTERNAL_API_KEY || key !== INTERNAL_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }
  next();
}

router.use(requireInternalKey);

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

    if (result.deducted && result.newBalanceCents != null) {
      checkAndDispatchBalanceAlerts(body.organization_id, result.newBalanceCents).catch(() => {});
      maybeAutoRecharge(body.organization_id).catch(() => {});
    }

    res.json({
      deducted: result.deducted,
      new_balance_cents: result.newBalanceCents,
      reason: result.reason ?? null,
      cog_cents: cogCents,
      charged_cents: chargedCents,
    });
  } catch (err) {
    console.error('[internal-billing.meter-event] failed', err);
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
