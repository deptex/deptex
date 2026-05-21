/**
 * v2.1d — Recorded-login step editor (inline inside DastAuthPanel).
 *
 * Self-contained component that owns the recorded-step authoring state:
 * step list with action picker / selector / value / timeout, credentials
 * block (username/password/TOTP), timing block, and the Test-login button
 * + result banner powered by useJobResult.
 *
 * Emits the full RecordedCredentialPayload via onChange so DastAuthPanel's
 * Save button can assemble the upsert request without knowing the step
 * editor internals.
 *
 * UI scope per pragmatist-f3 + Henry's "match competitors" steer: 9 step
 * actions, CSS/XPath selectors, per-step timeout, up/down sort. No
 * drag-handle in v1 (chevrons only) — deferred per the plan's open question.
 */

import { useEffect, useMemo, useState } from 'react';
import { Loader2, Plus, Trash2, ChevronUp, ChevronDown, CheckCircle2, AlertTriangle, X } from 'lucide-react';

import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import {
  api,
  type DastJobErrorPayload,
  type FailedAtStep,
  type RecordedCredentialPayload,
  type RecordedStep,
  type RecordedStepAction,
} from '../../lib/api';
import { useJobResult } from '../../hooks/useJobResult';

interface RecordedStrategyEditorProps {
  projectId: string;
  targetId: string;
  /** Called on every change so the parent's Save button stays in sync. */
  onChange: (payload: RecordedCredentialPayload | null) => void;
  disabled?: boolean;
}

const STEP_ACTIONS: { value: RecordedStepAction; label: string; needsSelector: boolean; needsValue: boolean; needsWaitMs: boolean }[] = [
  { value: 'goto',          label: 'Go to URL',         needsSelector: false, needsValue: true,  needsWaitMs: false },
  { value: 'click',         label: 'Click',             needsSelector: true,  needsValue: false, needsWaitMs: false },
  { value: 'type_username', label: 'Type username',     needsSelector: true,  needsValue: false, needsWaitMs: false },
  { value: 'type_password', label: 'Type password',     needsSelector: true,  needsValue: false, needsWaitMs: false },
  { value: 'type_totp',     label: 'Type TOTP code',    needsSelector: true,  needsValue: false, needsWaitMs: false },
  { value: 'type_custom',   label: 'Type custom value', needsSelector: true,  needsValue: true,  needsWaitMs: false },
  { value: 'wait',          label: 'Wait',              needsSelector: false, needsValue: false, needsWaitMs: true  },
  { value: 'return',        label: 'Press Enter',       needsSelector: false, needsValue: false, needsWaitMs: false },
  { value: 'escape',        label: 'Press Escape',      needsSelector: false, needsValue: false, needsWaitMs: false },
];

function findActionSpec(action: RecordedStepAction) {
  return STEP_ACTIONS.find((a) => a.value === action) ?? STEP_ACTIONS[1];
}

function emptyStep(action: RecordedStepAction = 'click'): RecordedStep {
  const spec = findActionSpec(action);
  return {
    action,
    selector: spec.needsSelector ? '' : undefined,
    selector_kind: spec.needsSelector ? 'css' : undefined,
    value: spec.needsValue ? '' : undefined,
    timeout_ms: spec.needsSelector ? 1000 : undefined,
    wait_ms: spec.needsWaitMs ? 500 : undefined,
  };
}

export function RecordedStrategyEditor({
  projectId,
  targetId,
  onChange,
  disabled,
}: RecordedStrategyEditorProps) {
  // Internal editor state.
  const [label, setLabel] = useState('');
  const [loginPageUrl, setLoginPageUrl] = useState('');
  const [steps, setSteps] = useState<RecordedStep[]>(() => [emptyStep('goto')]);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpSecret, setTotpSecret] = useState('');
  const [loginPageWaitMs, setLoginPageWaitMs] = useState(5000);
  const [stepDelayMs, setStepDelayMs] = useState(0);

  // Test-login flow state.
  const [testJobId, setTestJobId] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const [conflictJobId, setConflictJobId] = useState<string | null>(null);
  const [cancellingScan, setCancellingScan] = useState(false);

  const jobResult = useJobResult(testJobId, { projectId });

  // Assemble the payload value from the editor state. The memoization keys
  // on the primitive fields + the steps array reference; the parent's
  // onChange callback fires from a separate useEffect (NOT inside useMemo —
  // that would be a side effect during render and cause an infinite loop
  // because every render produces a fresh object identity).
  const payload = useMemo<RecordedCredentialPayload | null>(() => {
    if (!loginPageUrl || !username || !password || steps.length === 0) return null;
    return {
      kind: 'recorded',
      login_page_url: loginPageUrl.trim(),
      steps,
      username,
      password,
      ...(totpSecret ? { totp_secret: totpSecret } : {}),
      login_page_wait_ms: loginPageWaitMs,
      step_delay_ms: stepDelayMs,
      ...(label.trim() ? { label: label.trim() } : {}),
    };
  }, [loginPageUrl, steps, username, password, totpSecret, loginPageWaitMs, stepDelayMs, label]);

  useEffect(() => {
    onChange(payload);
    // We INTENTIONALLY want this to fire whenever the assembled payload
    // changes; the parent's setDraft is idempotent on equal values so this
    // doesn't loop. The onChange dependency would loop if the parent
    // recreated the callback every render — DastAuthPanel uses an inline
    // arrow which IS recreated; the cost is one extra notify per parent
    // re-render, which is acceptable.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [payload]);

  // Step manipulation helpers.
  function addStep() {
    setSteps((arr) => [...arr, emptyStep('click')]);
  }
  function removeStep(i: number) {
    setSteps((arr) => arr.filter((_, idx) => idx !== i));
  }
  function moveStep(i: number, dir: -1 | 1) {
    setSteps((arr) => {
      const next = arr.slice();
      const j = i + dir;
      if (j < 0 || j >= next.length) return next;
      const tmp = next[i];
      next[i] = next[j];
      next[j] = tmp;
      return next;
    });
  }
  function setStepField<K extends keyof RecordedStep>(i: number, key: K, value: RecordedStep[K]) {
    setSteps((arr) => {
      const next = arr.slice();
      next[i] = { ...next[i], [key]: value };
      return next;
    });
  }
  function setStepAction(i: number, action: RecordedStepAction) {
    setSteps((arr) => {
      const next = arr.slice();
      const oldStep = next[i];
      const fresh = emptyStep(action);
      // Preserve selector when both old and new actions take one.
      const oldSpec = findActionSpec(oldStep.action);
      const newSpec = findActionSpec(action);
      if (oldSpec.needsSelector && newSpec.needsSelector && oldStep.selector) {
        fresh.selector = oldStep.selector;
        fresh.selector_kind = oldStep.selector_kind ?? 'css';
      }
      next[i] = fresh;
      return next;
    });
  }

  // v2.1d /criticalreview EHA-2 (P2): map every known backend error code +
  // HTTP-status fallback to a friendly user-facing message. Without this,
  // 422/409 responses that carry `code`+`detail` (no `error` field) surface
  // as the literal "HTTP error! status: 422" from fetchWithAuth, and slug
  // responses like 'target_not_found' surface verbatim. Per memory
  // feedback_no_raw_errors_to_users.md, user-facing errors must be generic
  // and friendly while the raw cause goes to console.error.
  function friendlyTestErrorMessage(rawMessage: string, fallback: string): {
    message: string;
    isConflict: boolean;
  } {
    // Slug-shaped backend errors come through fetchWithAuth's body.error
    // field. Map every shape the routes can emit.
    if (rawMessage.includes('project_concurrent_dast_blocked')) {
      return {
        message: 'A scan is running on this target. Cancel it to test your login.',
        isConflict: true,
      };
    }
    if (rawMessage.includes('fly_machine_unavailable')) {
      return { message: 'Worker unavailable — try again in 30 seconds.', isConflict: false };
    }
    if (rawMessage.includes('target_not_found')) {
      return { message: "This target is no longer available.", isConflict: false };
    }
    if (rawMessage.includes('target_disabled')) {
      return {
        message: 'This target is disabled. Enable it in target settings to run a Test-login.',
        isConflict: false,
      };
    }
    if (rawMessage.includes('credentials_not_set')) {
      return {
        message: 'Save the credential first, then click Test login.',
        isConflict: false,
      };
    }
    if (rawMessage.includes('org_concurrent_dast_cap')) {
      return {
        message: 'Your organization is at the 5-concurrent DAST scan cap. Wait for one to finish.',
        isConflict: false,
      };
    }
    if (rawMessage.includes('unsupported_strategy_for_test')) {
      return {
        message: "Test login only supports the 'recorded' auth strategy.",
        isConflict: false,
      };
    }
    if (rawMessage.includes('login_url_invalid')) {
      return {
        message: 'The login page URL points to a private or unreachable host.',
        isConflict: false,
      };
    }
    if (rawMessage.includes('invalid_payload')) {
      return {
        message: 'The Test-login request was malformed — refresh and try again.',
        isConflict: false,
      };
    }
    if (rawMessage.includes('permission')) {
      return {
        message: "You don't have permission to run Test login on this project.",
        isConflict: false,
      };
    }
    // HTTP-status fallback: fetchWithAuth emits 'HTTP error! status: NNN'
    // when the response has no `error` field (e.g. 422/409 responses that
    // use `code`+`detail`). Surface a generic friendly message and log the
    // raw text for ops diagnosis.
    if (/HTTP error! status:\s*\d{3}/.test(rawMessage)) {
      return { message: fallback, isConflict: false };
    }
    return { message: fallback, isConflict: false };
  }

  // Test-login flow.
  async function startTest() {
    setTesting(true);
    setTestError(null);
    setConflictJobId(null);
    setTestJobId(null);
    try {
      const r = await api.postDastLoginTest(projectId, targetId);
      setTestJobId(r.test_job_id);
    } catch (e: unknown) {
      const rawMessage = e instanceof Error ? e.message : String(e);
      // Log the raw cause for ops; never display it to the user.
      // eslint-disable-next-line no-console
      console.error('[recorded-strategy-editor] Test-login failed:', rawMessage);
      const { message, isConflict } = friendlyTestErrorMessage(
        rawMessage,
        'Test login could not be started. Try again in a moment.',
      );
      setTestError(message);
      if (isConflict) {
        // 409 body carries conflict_job_id (v2.1d /criticalreview BAD-3 +
        // RSS-2 fix). fetchWithAuth attaches the parsed body as
        // responseBody on the thrown Error; read it for the conflicting
        // job id. Fall back to 'unknown' if the backend hasn't shipped the
        // new field yet (during a partial rollout, the Cancel button stays
        // hidden but the banner still shows).
        const body = (e as Error & { responseBody?: { conflict_job_id?: string | null } })
          .responseBody;
        setConflictJobId(body?.conflict_job_id ?? 'unknown');
      }
    } finally {
      setTesting(false);
    }
  }

  async function cancelConflictingScan() {
    if (!conflictJobId || conflictJobId === 'unknown') return;
    setCancellingScan(true);
    try {
      await api.cancelDastJob(projectId, conflictJobId);
      setTestError(null);
      setConflictJobId(null);
      await startTest();
    } catch (e: unknown) {
      const rawMessage = e instanceof Error ? e.message : String(e);
      // eslint-disable-next-line no-console
      console.error('[recorded-strategy-editor] Cancel-running-scan failed:', rawMessage);
      const { message } = friendlyTestErrorMessage(
        rawMessage,
        "Couldn't cancel the running scan. Refresh and try again.",
      );
      setTestError(message);
    } finally {
      setCancellingScan(false);
    }
  }

  const banner = renderResultBanner(testing, jobResult.status, jobResult.job?.error_payload ?? null, testError);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <Label className="text-sm text-foreground">Label (optional)</Label>
          <Input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            disabled={disabled}
            placeholder="Prod login"
            maxLength={80}
            className="mt-1 text-xs"
          />
        </div>
        <div>
          <Label className="text-sm text-foreground">Login page URL</Label>
          <Input
            type="url"
            value={loginPageUrl}
            onChange={(e) => setLoginPageUrl(e.target.value)}
            disabled={disabled}
            placeholder="https://app.example.com/login"
            className="mt-1 font-mono text-xs"
          />
        </div>
      </div>

      <div>
        <div className="flex items-center justify-between mb-2">
          <Label className="text-sm text-foreground">Login steps</Label>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={addStep}
            disabled={disabled}
          >
            <Plus className="h-3.5 w-3.5 mr-1" />
            Add step
          </Button>
        </div>
        <div className="rounded-md border border-border divide-y divide-border">
          {steps.map((step, i) => (
            <StepRow
              key={i}
              index={i}
              step={step}
              isFailedStep={isFailedStepIndex(jobResult.job?.error_payload ?? null, i)}
              isFirstStep={i === 0}
              isLastStep={i === steps.length - 1}
              disabled={disabled}
              onChange={(key, value) => setStepField(i, key, value)}
              onAction={(a) => setStepAction(i, a)}
              onRemove={() => removeStep(i)}
              onMoveUp={() => moveStep(i, -1)}
              onMoveDown={() => moveStep(i, 1)}
            />
          ))}
        </div>
        {steps.length === 0 ? (
          <p className="text-xs text-foreground-muted mt-2">No steps yet — click "Add step".</p>
        ) : null}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <Label className="text-sm text-foreground">Username</Label>
          <Input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={disabled}
            placeholder="alice@example.com"
            autoComplete="off"
            className="mt-1 text-xs"
          />
        </div>
        <div>
          <Label className="text-sm text-foreground">Password</Label>
          <Input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={disabled}
            autoComplete="new-password"
            className="mt-1 text-xs"
          />
        </div>
        <div>
          <Label className="text-sm text-foreground">TOTP secret (optional)</Label>
          <Input
            type="password"
            value={totpSecret}
            onChange={(e) => setTotpSecret(e.target.value.toUpperCase())}
            disabled={disabled}
            autoComplete="off"
            placeholder="JBSWY3DPEHPK3PXP"
            className="mt-1 font-mono text-xs"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <Label className="text-sm text-foreground">Login-page wait (ms)</Label>
          <Input
            type="number"
            min={0}
            max={30000}
            value={loginPageWaitMs}
            onChange={(e) => setLoginPageWaitMs(Number(e.target.value) || 0)}
            disabled={disabled}
            className="mt-1 text-xs"
          />
        </div>
        <div>
          <Label className="text-sm text-foreground">Step delay (ms)</Label>
          <Input
            type="number"
            min={0}
            max={5000}
            value={stepDelayMs}
            onChange={(e) => setStepDelayMs(Number(e.target.value) || 0)}
            disabled={disabled}
            className="mt-1 text-xs"
          />
        </div>
      </div>

      {/* Test-login row. */}
      <div className="flex items-center justify-between gap-2 pt-1">
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={startTest}
            disabled={disabled || testing || !payload || jobResult.status === 'polling' || jobResult.status === 'still_running'}
          >
            {testing || jobResult.status === 'polling' || jobResult.status === 'still_running' ? (
              <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" />
            ) : (
              <CheckCircle2 className="h-3.5 w-3.5 mr-2" />
            )}
            Test login
          </Button>
          {conflictJobId && conflictJobId !== 'unknown' ? (
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={cancelConflictingScan}
              disabled={cancellingScan}
            >
              {cancellingScan ? <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" /> : <X className="h-3.5 w-3.5 mr-2" />}
              Cancel running scan
            </Button>
          ) : null}
        </div>
      </div>

      {banner}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Step row
// ---------------------------------------------------------------------------

interface StepRowProps {
  index: number;
  step: RecordedStep;
  isFailedStep: boolean;
  isFirstStep: boolean;
  isLastStep: boolean;
  disabled?: boolean;
  onChange: <K extends keyof RecordedStep>(key: K, value: RecordedStep[K]) => void;
  onAction: (a: RecordedStepAction) => void;
  onRemove: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}

function StepRow({
  index,
  step,
  isFailedStep,
  isFirstStep,
  isLastStep,
  disabled,
  onChange,
  onAction,
  onRemove,
  onMoveUp,
  onMoveDown,
}: StepRowProps) {
  const spec = findActionSpec(step.action);
  // Validation: goto only allowed at index 0.
  const gotoMisplaced = step.action === 'goto' && index !== 0;
  return (
    <div className={`flex items-center gap-2 px-2 py-2 ${isFailedStep ? 'bg-destructive/5 border-l-2 border-destructive' : ''}`}>
      <span className="text-xs text-foreground-muted w-6">{index + 1}</span>
      <Select value={step.action} onValueChange={(v) => onAction(v as RecordedStepAction)} disabled={disabled}>
        <SelectTrigger className="w-[170px] text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {STEP_ACTIONS.map((a) => (
            <SelectItem key={a.value} value={a.value}>{a.label}</SelectItem>
          ))}
        </SelectContent>
      </Select>
      {spec.needsSelector ? (
        <>
          <Select
            value={step.selector_kind ?? 'css'}
            onValueChange={(v) => onChange('selector_kind', v as 'css' | 'xpath')}
            disabled={disabled}
          >
            <SelectTrigger className="w-[80px] text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="css">CSS</SelectItem>
              <SelectItem value="xpath">XPath</SelectItem>
            </SelectContent>
          </Select>
          <Input
            value={step.selector ?? ''}
            onChange={(e) => onChange('selector', e.target.value)}
            disabled={disabled}
            placeholder={step.selector_kind === 'xpath' ? '//button[@type="submit"]' : '#email'}
            className="flex-1 font-mono text-xs"
          />
        </>
      ) : null}
      {spec.needsValue ? (
        <Input
          value={step.value ?? ''}
          onChange={(e) => onChange('value', e.target.value)}
          disabled={disabled}
          placeholder={step.action === 'goto' ? 'https://…' : 'value'}
          className="flex-1 font-mono text-xs"
          type={step.action === 'type_custom' ? 'password' : 'text'}
          autoComplete="off"
        />
      ) : null}
      {spec.needsWaitMs ? (
        <Input
          type="number"
          min={0}
          max={30000}
          value={step.wait_ms ?? 500}
          onChange={(e) => onChange('wait_ms', Number(e.target.value) || 0)}
          disabled={disabled}
          className="w-[100px] text-xs"
          placeholder="ms"
        />
      ) : null}
      <div className="flex items-center gap-1 ml-auto">
        <Button type="button" variant="ghost" size="sm" disabled={disabled || isFirstStep} onClick={onMoveUp}>
          <ChevronUp className="h-3.5 w-3.5" />
        </Button>
        <Button type="button" variant="ghost" size="sm" disabled={disabled || isLastStep} onClick={onMoveDown}>
          <ChevronDown className="h-3.5 w-3.5" />
        </Button>
        <Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={onRemove}>
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
      {gotoMisplaced ? (
        <span className="text-[11px] text-destructive ml-2">Only step 1 can be "Go to URL".</span>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Result banner
// ---------------------------------------------------------------------------

function isFailedStepIndex(payload: DastJobErrorPayload | null, idx: number): boolean {
  if (!payload) return false;
  if (payload.kind === 'test_result' && payload.test_result.failed_at_step) {
    return payload.test_result.failed_at_step.step_index === idx;
  }
  if (payload.kind === 'pre_flight_failed') {
    return payload.failed_at_step.step_index === idx;
  }
  return false;
}

function renderResultBanner(
  testing: boolean,
  pollStatus: ReturnType<typeof useJobResult>['status'],
  payload: DastJobErrorPayload | null,
  testError: string | null,
) {
  if (testError) {
    return (
      <div className="flex items-center gap-2 text-xs text-destructive">
        <AlertTriangle className="h-3.5 w-3.5" />
        <span>{testError}</span>
      </div>
    );
  }
  if (testing || pollStatus === 'polling') {
    return (
      <div className="flex items-center gap-2 text-xs text-foreground-secondary">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        <span>Running login test…</span>
      </div>
    );
  }
  if (pollStatus === 'still_running') {
    return (
      <div className="flex items-center gap-2 text-xs text-foreground-secondary">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        <span>Still running — SSO or cold start can take 2-3 min.</span>
      </div>
    );
  }
  if (pollStatus === 'timeout') {
    return (
      <div className="flex items-center gap-2 text-xs text-destructive">
        <AlertTriangle className="h-3.5 w-3.5" />
        <span>Test timed out. Try again or simplify the login flow.</span>
      </div>
    );
  }
  if (pollStatus === 'error') {
    return (
      <div className="flex items-center gap-2 text-xs text-destructive">
        <AlertTriangle className="h-3.5 w-3.5" />
        <span>Network error polling test result. Try again.</span>
      </div>
    );
  }
  if (!payload) return null;
  if (payload.kind === 'test_result') {
    const r = payload.test_result;
    if (r.success) {
      return (
        <div className="flex items-center gap-2 text-xs text-emerald-500">
          <CheckCircle2 className="h-3.5 w-3.5" />
          <span>Logged in — {(r.duration_ms / 1000).toFixed(1)}s, {r.steps_run} steps.</span>
        </div>
      );
    }
    return (
      <div className="space-y-1">
        <div className="flex items-center gap-2 text-xs text-destructive">
          <AlertTriangle className="h-3.5 w-3.5" />
          <span>{formatFailure(r.failed_at_step ?? null)}</span>
        </div>
        {r.raw_log ? (
          <details className="text-[11px] text-foreground-muted">
            <summary className="cursor-pointer">Show raw log</summary>
            <pre className="mt-1 overflow-auto rounded bg-background-card p-2 font-mono">{r.raw_log}</pre>
          </details>
        ) : null}
      </div>
    );
  }
  return null;
}

function formatFailure(failed: FailedAtStep | null): string {
  if (!failed) return 'Test login failed for an unknown reason.';
  const stepLabel = `Step ${failed.step_index + 1} (${failed.action})`;
  const reasonText: Record<FailedAtStep['reason'], string> = {
    selector_not_visible_after_timeout: `selector ${failed.selector ?? ''} was not visible in time`,
    cross_origin_blocked: 'cross-origin navigation was blocked',
    totp_generation_failed: 'TOTP code generation failed',
    browser_crashed: 'the browser crashed during this step',
    logged_in_indicator_missed: 'logged-in indicator did not match after login',
    logged_out_indicator_present_after_login: 'logged-out indicator was still present after login',
    unknown: 'an unknown error occurred',
  };
  return `${stepLabel}: ${reasonText[failed.reason]}`;
}
