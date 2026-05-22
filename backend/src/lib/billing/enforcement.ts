export function isBillingEnforcementEnabled(): boolean {
  return process.env.DEPTEX_BILLING_ENFORCEMENT === 'on';
}
