export type MeterEventType = 'ai_tokens' | 'worker_minutes';
export type MeterProvider  = 'openai' | 'anthropic' | 'google' | 'deepinfra' | 'fly';
export type MeterUnit      = 'input_tokens' | 'output_tokens' | 'seconds' | 'mixed_tokens';
export type AttributionResourceType = 'aegis_chat' | 'scan_job' | 'fix_task' | 'rule_generation' | 'epd_scoring';

export type TransactionKind =
  | 'signup_grant'
  | 'topup'
  | 'auto_recharge_topup'
  | 'usage_deduction'
  | 'refund'
  | 'adjustment';

export interface MeterAttribution {
  userId?: string;
  resourceType?: AttributionResourceType;
  resourceId?: string;
}

export interface RecordMeterEventInput {
  organizationId: string;
  /** Optional — populated for worker events (depscanner.*, fix-worker.task)
   * where the resource is tied to a project. Aegis chats and EPD scoring
   * are cross-project, leave null. */
  projectId?: string;
  eventType: MeterEventType;
  provider: MeterProvider;
  feature: string;
  quantity: number;
  outputQuantity?: number;
  unit: MeterUnit;
  cogCents: number;
  chargedCents: number;
  modelId?: string;
  machineSize?: string;
  attribution?: MeterAttribution;
  idempotencyKey: string;
}

export interface RecordMeterEventResult {
  deducted: boolean;
  newBalanceCents: number | null;
  reason?: 'insufficient_credit' | 'enforcement_off' | 'duplicate_idempotency_key';
}

export interface CanChargeResponse {
  allowed: boolean;
  balanceCents: number;
  reason?: 'insufficient_credit' | 'enforcement_off';
}

export interface BillingPaymentMethod {
  brand: string;
  last4: string;
  expiresMonth: number;
  expiresYear: number;
}

export interface BillingState {
  balanceCents: number;
  autoRecharge: {
    enabled: boolean;
    thresholdCents: number | null;
    amountCents: number | null;
    monthlyCapCents: number | null;
  };
  lowBalanceAlertThresholdCents: number;
  billingEmailOverride: string | null;
  paymentMethod: BillingPaymentMethod | null;
}

export interface TopUpResponse {
  clientSecret: string;
  paymentIntentId: string;
  amountCents: number;
}

export interface BillingTransaction {
  id: string;
  kind: TransactionKind;
  amountCents: number;
  description: string;
  createdAt: string;
  stripePaymentIntentId: string | null;
}

export interface UsageActivity {
  id: string;
  feature: string;
  eventType: MeterEventType;
  costCentsCharged: number;
  emittedAt: string;
  attribution: {
    userId: string | null;
    resourceType: AttributionResourceType | null;
    resourceId: string | null;
  };
  modelId: string | null;
  machineSize: string | null;
}

export interface UsageResponse {
  totalCents: number;
  activity: UsageActivity[];
  nextCursor: string | null;
}

export interface TransactionsResponse {
  transactions: BillingTransaction[];
  nextCursor: string | null;
}

export type PaymentIntentPurpose = 'topup' | 'auto_recharge_topup';
