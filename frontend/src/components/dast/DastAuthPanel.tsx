import { useEffect, useState } from 'react';
import { Loader2, CheckCircle2, ShieldCheck, Trash2, Plus, AlertTriangle } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { Badge } from '../ui/badge';
import { useToast } from '../../hooks/use-toast';
import {
  api,
  type DastAuthStrategy,
  type DastCredentialSummaryDTO,
  type DastCredentialUpsertDTO,
  type DastCredentialUpsertPayload,
  type RecordedCredentialPayload,
} from '../../lib/api';
import { RecordedStrategyEditor } from './RecordedStrategyEditor';

interface DastAuthPanelProps {
  projectId: string;
  targetId: string;
  /** The currently configured (redacted) credential, or null if anonymous. */
  initialSummary: DastCredentialSummaryDTO | null;
  /** Called when a credential is saved or removed so the parent can refresh. */
  onChange?: () => void;
  disabled?: boolean;
}

type CookieDraft = { name: string; value: string };

interface DraftState {
  strategy: DastAuthStrategy;
  // form
  loginUrl: string;
  usernameField: string;
  passwordField: string;
  username: string;
  password: string;
  // jwt
  token: string;
  // cookie
  cookies: CookieDraft[];
  // recorded — owned by the inline RecordedStrategyEditor component which
  // emits an assembled payload via onChange. Stored here so buildPayload can
  // assemble the upsert request from one source of truth.
  recordedPayload: RecordedCredentialPayload | null;
  // common
  loggedInIndicator: string;
  loggedOutIndicator: string;
}

const STRATEGY_OPTIONS: { value: DastAuthStrategy; label: string }[] = [
  { value: 'form', label: 'Form login' },
  { value: 'jwt', label: 'JWT bearer' },
  { value: 'cookie', label: 'Session cookies' },
  { value: 'recorded', label: 'Recorded login (v2.1d)' },
];

function emptyDraft(strategy: DastAuthStrategy): DraftState {
  return {
    strategy,
    loginUrl: '',
    usernameField: 'username',
    passwordField: 'password',
    username: '',
    password: '',
    token: '',
    cookies: [{ name: '', value: '' }],
    recordedPayload: null,
    loggedInIndicator: '',
    loggedOutIndicator: '',
  };
}

function buildPayload(draft: DraftState): DastCredentialUpsertPayload | null {
  if (draft.strategy === 'form') {
    if (!draft.loginUrl || !draft.username || !draft.password) return null;
    return {
      kind: 'form',
      login_url: draft.loginUrl.trim(),
      username_field: draft.usernameField.trim() || 'username',
      password_field: draft.passwordField.trim() || 'password',
      username: draft.username,
      password: draft.password,
    };
  }
  if (draft.strategy === 'jwt') {
    if (!draft.token) return null;
    return { kind: 'jwt', token: draft.token.trim() };
  }
  if (draft.strategy === 'recorded') {
    return draft.recordedPayload;
  }
  const validCookies = draft.cookies
    .map((c) => ({ name: c.name.trim(), value: c.value }))
    .filter((c) => c.name.length > 0 && c.value.length > 0);
  if (validCookies.length === 0) return null;
  return { kind: 'cookie', cookies: validCookies };
}

export function DastAuthPanel({
  projectId,
  targetId,
  initialSummary,
  onChange,
  disabled,
}: DastAuthPanelProps) {
  const { toast } = useToast();
  const [draft, setDraft] = useState<DraftState>(() =>
    emptyDraft(initialSummary?.auth_strategy ?? 'form'),
  );
  const [saving, setSaving] = useState(false);
  const [removing, setRemoving] = useState(false);
  const [lastResult, setLastResult] = useState<
    { kind: 'success'; message: string } | { kind: 'error'; message: string } | null
  >(null);

  useEffect(() => {
    setDraft((d) => ({
      ...d,
      strategy: initialSummary?.auth_strategy ?? d.strategy,
      loggedInIndicator: initialSummary?.logged_in_indicator ?? '',
      loggedOutIndicator: initialSummary?.logged_out_indicator ?? '',
    }));
  }, [initialSummary?.auth_strategy, initialSummary?.logged_in_indicator, initialSummary?.logged_out_indicator]);

  const submit = async () => {
    const payload = buildPayload(draft);
    if (!payload) {
      setLastResult({ kind: 'error', message: 'Fill in the required fields above.' });
      return;
    }
    setSaving(true);
    setLastResult(null);
    try {
      const body: DastCredentialUpsertDTO = {
        auth_strategy: draft.strategy,
        payload,
        logged_in_indicator: draft.loggedInIndicator || undefined,
        logged_out_indicator: draft.loggedOutIndicator || undefined,
      };
      await api.putDastTargetCredentials(projectId, targetId, body);
      setLastResult({
        kind: 'success',
        message:
          draft.strategy === 'form'
            ? 'Login probe succeeded — credential saved.'
            : 'Credential validated and saved.',
      });
      // Wipe secret fields after a successful save so they don't linger in DOM.
      setDraft((d) => ({ ...d, password: '', token: '', cookies: d.cookies.map((c) => ({ ...c, value: '' })) }));
      onChange?.();
    } catch (e: any) {
      const code = e?.message ?? 'Failed to save credential';
      setLastResult({ kind: 'error', message: humanizeAuthError(code) });
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    setRemoving(true);
    try {
      await api.deleteDastTargetCredentials(projectId, targetId);
      setLastResult({ kind: 'success', message: 'Credential removed — target reverts to anonymous.' });
      setDraft(emptyDraft(draft.strategy));
      onChange?.();
    } catch (e: any) {
      toast({
        title: 'Failed to remove credential',
        description: e?.message,
        variant: 'destructive',
      });
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <Label className="text-sm text-foreground">Authentication strategy</Label>
        <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
          ZAP authenticates the scan via this strategy. Recorded login (HAR replay) ships in v2.1d.
        </p>
        <Select
          value={draft.strategy}
          onValueChange={(v) => setDraft((d) => ({ ...emptyDraft(v as DastAuthStrategy), loggedInIndicator: d.loggedInIndicator, loggedOutIndicator: d.loggedOutIndicator }))}
          disabled={disabled || saving}
        >
          <SelectTrigger className="max-w-[260px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STRATEGY_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {initialSummary ? <CurrentCredentialSummary summary={initialSummary} /> : null}

      {draft.strategy === 'form' && (
        <FormStrategyFields draft={draft} setDraft={setDraft} disabled={disabled || saving} />
      )}
      {draft.strategy === 'jwt' && (
        <JwtStrategyFields draft={draft} setDraft={setDraft} disabled={disabled || saving} />
      )}
      {draft.strategy === 'cookie' && (
        <CookieStrategyFields draft={draft} setDraft={setDraft} disabled={disabled || saving} />
      )}
      {draft.strategy === 'recorded' && (
        <RecordedStrategyEditor
          projectId={projectId}
          targetId={targetId}
          onChange={(payload) => setDraft((d) => ({ ...d, recordedPayload: payload }))}
          disabled={disabled || saving}
        />
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div>
          <Label htmlFor="dast-auth-logged-in" className="text-sm text-foreground">Logged-in indicator</Label>
          <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
            Regex that matches a string only present when authenticated (e.g. <code>Sign out</code>).
          </p>
          <Input
            id="dast-auth-logged-in"
            value={draft.loggedInIndicator}
            onChange={(e) => setDraft((d) => ({ ...d, loggedInIndicator: e.target.value }))}
            disabled={disabled || saving}
            placeholder="Sign out"
            className="font-mono text-xs"
          />
        </div>
        <div>
          <Label htmlFor="dast-auth-logged-out" className="text-sm text-foreground">Logged-out indicator</Label>
          <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
            Regex on a logged-out response (e.g. <code>Login</code>). Triggers re-login or auth-lost.
          </p>
          <Input
            id="dast-auth-logged-out"
            value={draft.loggedOutIndicator}
            onChange={(e) => setDraft((d) => ({ ...d, loggedOutIndicator: e.target.value }))}
            disabled={disabled || saving}
            placeholder="Login"
            className="font-mono text-xs"
          />
        </div>
      </div>

      {lastResult ? (
        <div
          className={
            lastResult.kind === 'success'
              ? 'flex items-center gap-2 text-xs text-emerald-500'
              : 'flex items-center gap-2 text-xs text-destructive'
          }
        >
          {lastResult.kind === 'success' ? (
            <CheckCircle2 className="h-3.5 w-3.5" />
          ) : (
            <AlertTriangle className="h-3.5 w-3.5" />
          )}
          <span>{lastResult.message}</span>
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-2 pt-1">
        {initialSummary ? (
          <Button
            variant="outline"
            size="sm"
            onClick={remove}
            disabled={disabled || removing || saving}
          >
            {removing ? <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" /> : <Trash2 className="h-3.5 w-3.5 mr-2" />}
            Remove credential
          </Button>
        ) : <span />}
        <Button
          variant="outline"
          size="sm"
          onClick={submit}
          disabled={disabled || saving}
        >
          {saving ? <Loader2 className="h-3.5 w-3.5 mr-2 animate-spin" /> : <ShieldCheck className="h-3.5 w-3.5 mr-2" />}
          {draft.strategy === 'form' ? 'Test login & save' : 'Save credential'}
        </Button>
      </div>
    </div>
  );
}

function humanizeAuthError(code: string): string {
  switch (code) {
    case 'jwt_expired_too_soon':
      return 'JWT expires before the scan would finish. Use a longer-lived token.';
    case 'jwt_missing_exp':
      return 'JWT has no expiry claim. Refusing to use a non-expiring token.';
    case 'jwt_malformed':
      return 'JWT is not a valid token (could not decode).';
    case 'login_probe_failed_indicator_collision':
      return 'Both logged-in and logged-out indicators matched the same response. Fix the regex.';
    case 'login_probe_failed':
      return 'Login probe failed — the username/password combo did not authenticate.';
    case 'login_probe_unreachable':
      return 'Could not reach the login URL (DNS / SSRF / timeout).';
    case 'invalid_payload':
      return 'Required fields are missing or malformed.';
    case 'dast_encryption_not_configured':
      return 'Server is missing DAST_CREDENTIAL_KEY. Contact your admin.';
    case 'invalid_target_url':
      return 'Login URL is invalid or points at a private host.';
    default:
      return 'Failed to save credential. See console for details.';
  }
}

function CurrentCredentialSummary({ summary }: { summary: DastCredentialSummaryDTO }) {
  let detail = '';
  if (summary.payload_summary.kind === 'form') {
    detail = `Form login as ${summary.payload_summary.username_masked}`;
  } else if (summary.payload_summary.kind === 'jwt') {
    detail = `JWT (${summary.payload_summary.token_prefix}, expires in ${summary.payload_summary.expires_in_minutes}m)`;
  } else if (summary.payload_summary.kind === 'recorded') {
    const labelStr = summary.payload_summary.label ? `${summary.payload_summary.label} — ` : '';
    detail = `${labelStr}${summary.payload_summary.step_count}-step recorded login on ${summary.payload_summary.login_page_url_host}${summary.payload_summary.has_totp ? ' (with TOTP)' : ''}`;
  } else {
    detail = `${summary.payload_summary.cookie_count} cookie${summary.payload_summary.cookie_count === 1 ? '' : 's'}`;
  }
  return (
    <div className="rounded-md border border-border bg-background-card-header px-3 py-2 flex items-center gap-2">
      <Badge variant="outline" className="capitalize text-[11px]">{summary.auth_strategy}</Badge>
      <span className="text-xs text-foreground-secondary">{detail}</span>
      <span className="ml-auto text-[11px] text-foreground-secondary">
        Updated {new Date(summary.updated_at).toLocaleString()}
      </span>
    </div>
  );
}

interface StrategyFieldsProps {
  draft: DraftState;
  setDraft: (fn: (prev: DraftState) => DraftState) => void;
  disabled?: boolean;
}

function FormStrategyFields({ draft, setDraft, disabled }: StrategyFieldsProps) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      <div className="md:col-span-2">
        <Label className="text-sm text-foreground">Login URL</Label>
        <Input
          type="url"
          value={draft.loginUrl}
          onChange={(e) => setDraft((d) => ({ ...d, loginUrl: e.target.value }))}
          disabled={disabled}
          placeholder="https://staging.example.com/login"
          className="mt-1 font-mono text-xs"
        />
      </div>
      <div>
        <Label className="text-sm text-foreground">Username field</Label>
        <Input
          value={draft.usernameField}
          onChange={(e) => setDraft((d) => ({ ...d, usernameField: e.target.value }))}
          disabled={disabled}
          className="mt-1 font-mono text-xs"
        />
      </div>
      <div>
        <Label className="text-sm text-foreground">Password field</Label>
        <Input
          value={draft.passwordField}
          onChange={(e) => setDraft((d) => ({ ...d, passwordField: e.target.value }))}
          disabled={disabled}
          className="mt-1 font-mono text-xs"
        />
      </div>
      <div>
        <Label className="text-sm text-foreground">Username</Label>
        <Input
          value={draft.username}
          onChange={(e) => setDraft((d) => ({ ...d, username: e.target.value }))}
          disabled={disabled}
          autoComplete="off"
          className="mt-1"
        />
      </div>
      <div>
        <Label className="text-sm text-foreground">Password</Label>
        <Input
          type="password"
          value={draft.password}
          onChange={(e) => setDraft((d) => ({ ...d, password: e.target.value }))}
          disabled={disabled}
          autoComplete="new-password"
          className="mt-1"
        />
      </div>
    </div>
  );
}

function JwtStrategyFields({ draft, setDraft, disabled }: StrategyFieldsProps) {
  return (
    <div>
      <Label className="text-sm text-foreground">Bearer token</Label>
      <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
        Sent as <code>Authorization: Bearer &lt;token&gt;</code> on every scan request. Token must
        have an <code>exp</code> claim that outlasts the scan timeout by at least 50%.
      </p>
      <Input
        value={draft.token}
        onChange={(e) => setDraft((d) => ({ ...d, token: e.target.value }))}
        disabled={disabled}
        autoComplete="off"
        placeholder="eyJhbGciOi..."
        className="font-mono text-xs"
      />
    </div>
  );
}

function CookieStrategyFields({ draft, setDraft, disabled }: StrategyFieldsProps) {
  const update = (i: number, patch: Partial<CookieDraft>) =>
    setDraft((d) => ({
      ...d,
      cookies: d.cookies.map((c, idx) => (idx === i ? { ...c, ...patch } : c)),
    }));
  const remove = (i: number) =>
    setDraft((d) => ({ ...d, cookies: d.cookies.filter((_, idx) => idx !== i) }));
  const add = () =>
    setDraft((d) => ({ ...d, cookies: [...d.cookies, { name: '', value: '' }] }));
  return (
    <div>
      <Label className="text-sm text-foreground">Session cookies</Label>
      <p className="text-xs text-foreground-secondary mt-0.5 mb-2">
        ZAP injects these cookies on every scan request via a replacer rule. Capture them after a
        manual login to staging.
      </p>
      <div className="space-y-1.5">
        {draft.cookies.map((cookie, i) => (
          <div key={i} className="flex items-center gap-2">
            <Input
              placeholder="connect.sid"
              value={cookie.name}
              onChange={(e) => update(i, { name: e.target.value })}
              disabled={disabled}
              className="font-mono text-xs flex-1"
            />
            <Input
              placeholder="s%3A..."
              value={cookie.value}
              onChange={(e) => update(i, { value: e.target.value })}
              disabled={disabled}
              autoComplete="off"
              className="font-mono text-xs flex-1"
            />
            {draft.cookies.length > 1 ? (
              <Button
                variant="outline"
                size="icon"
                onClick={() => remove(i)}
                disabled={disabled}
                aria-label="Remove cookie"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            ) : null}
          </div>
        ))}
        <Button variant="outline" size="sm" onClick={add} disabled={disabled}>
          <Plus className="h-3.5 w-3.5 mr-1" /> Add cookie
        </Button>
      </div>
    </div>
  );
}
