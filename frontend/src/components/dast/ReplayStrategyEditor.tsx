// Phase 36 (v1.1) — Replay-strategy editor for DAST credentials.
//
// User flow:
//   1. Drag-drop / pick a .har file (or paste from clipboard).
//   2. Client-side caps (.har extension + ≤1.5MB) reject before upload.
//   3. POST /replay/preview returns a scrubbed summary + non-replayable
//      warnings + auto-detected TOTP step. NO request is committed yet.
//   4. User adds optional TOTP secret + label, indicators come from the
//      parent (DastAuthPanel).
//   5. Save → parent calls PUT /credentials with the assembled
//      ReplayCredentialPayload (this component emits via onChange).
//   6. Test-replay → POST /credentials/test → poll via useJobResult.
//
// SYNCED PATTERN with RecordedStrategyEditor.tsx between // region:test-job-state
// and // endregion — the test-job state machine is duplicated here per
// Patch 5a. The v1.1 follow-up extracts both copies into a shared
// useDastTestJob() hook; until then bug-fixes here MUST also land in the
// recorded version (and vice versa). Tracked in dast_har_import_state.md
// v1.1 backlog.

import { useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Loader2, Upload, X } from 'lucide-react';

import {
  api,
  type DastReplayPreviewResponse,
  type HarTotpStep,
  type ReplayCredentialPayload,
  type ReplayedRequest,
} from '../../lib/api';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { useJobResult } from '../../hooks/useJobResult';
import { friendlyHarErrorMessage } from '../../lib/dast-error-codes';

interface ReplayStrategyEditorProps {
  projectId: string;
  targetId: string;
  onChange: (payload: ReplayCredentialPayload | null) => void;
  disabled?: boolean;
}

// Parsed-but-not-yet-committed state. The structural HAR bytes get held
// in-memory until the user clicks Save (which then encrypts + stores
// them via PUT /credentials). On every component unmount we wipe the
// in-memory copy.
interface PreviewState {
  preview: DastReplayPreviewResponse;
  // Reconstructed request list (what we'll send back at PUT time). The
  // preview response holds only scrubbed metadata; we hold the unscrubbed
  // requests separately so a Save sends the actual bytes ZAP needs.
  requests: ReplayedRequest[];
}

const MAX_HAR_BYTES = 1.5 * 1024 * 1024;

export function ReplayStrategyEditor({
  projectId,
  targetId,
  onChange,
  disabled,
}: ReplayStrategyEditorProps) {
  const [previewState, setPreviewState] = useState<PreviewState | null>(null);
  const [parseError, setParseError] = useState<string | null>(null);
  const [parsing, setParsing] = useState(false);
  const [totpSecret, setTotpSecret] = useState('');
  const [label, setLabel] = useState('');

  // region:test-job-state — synced pattern with RecordedStrategyEditor.tsx
  const [testJobId, setTestJobId] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);
  const jobResult = useJobResult(testJobId, { projectId });
  // endregion

  // Assembled payload. Re-derives when preview / totpSecret / label change.
  // The TOTP step (if detected) is included verbatim; totp_secret is omitted
  // when the user hasn't entered one (the validator accepts payloads
  // without it — the auth replays the captured static code, which works
  // until the next 30s window flips).
  const payload = useMemo<ReplayCredentialPayload | null>(() => {
    if (!previewState) return null;
    const trimmedSecret = totpSecret.trim();
    const trimmedLabel = label.trim();
    return {
      kind: 'replay',
      requests: previewState.requests,
      ...(previewState.preview.totp_detected
        ? { totp_step: previewState.preview.totp_detected as HarTotpStep }
        : {}),
      ...(trimmedSecret ? { totp_secret: trimmedSecret } : {}),
      origins_observed: previewState.preview.summary.origins,
      ...(trimmedLabel ? { label: trimmedLabel } : {}),
    };
  }, [previewState, totpSecret, label]);

  useEffect(() => {
    onChange(payload);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [payload]);

  // On unmount: wipe the HAR-derived requests from memory.
  useEffect(() => {
    return () => {
      setPreviewState(null);
      setTotpSecret('');
    };
  }, []);

  async function handleFile(file: File): Promise<void> {
    setParseError(null);
    if (!file.name.toLowerCase().endsWith('.har')) {
      setParseError('Only .har files (HTTP Archive 1.2). Export from Chrome DevTools → Network → ⋮ → Save all as HAR with content.');
      return;
    }
    if (file.size > MAX_HAR_BYTES) {
      setParseError(`HAR exceeds the 1.5 MB cap (received ${(file.size / 1024 / 1024).toFixed(2)} MB).`);
      return;
    }
    setParsing(true);
    try {
      const text = await file.text();
      let har: unknown;
      try {
        har = JSON.parse(text);
      } catch {
        setParseError("That file isn't valid JSON.");
        return;
      }
      const resp = await api.parseDastHar(projectId, targetId, har);
      // Pull the unscrubbed request list back out of the HAR ourselves so
      // Save can ship the bytes ZAP needs. (The preview response is
      // boolean-only by design; the FE re-extracts here.)
      const requests = extractRequestsFromHar(har);
      setPreviewState({ preview: resp, requests });
    } catch (e: any) {
      const raw = (e?.message ?? '').toString();
      // fetchWithAuth surfaces backend error_code in the message tail —
      // friendlyHarErrorMessage maps it to user copy.
      const codeMatch = raw.match(/\b(invalid_har_shape|har_too_large|har_too_small|har_entry_too_large|har_non_https_entry|har_private_ip_entry|har_origin_count_exceeded|har_no_replayable_requests|har_totp_secret_invalid|replay_payload_too_large|dast_encryption_not_configured)\b/);
      setParseError(friendlyHarErrorMessage(codeMatch?.[1], undefined));
    } finally {
      setParsing(false);
    }
  }

  // region:test-job-state — synced pattern with RecordedStrategyEditor.tsx
  async function runTest(): Promise<void> {
    setTesting(true);
    setTestError(null);
    setTestJobId(null);
    try {
      const resp = await api.postDastLoginTest(projectId, targetId);
      setTestJobId(resp.test_job_id);
    } catch (e: any) {
      const raw = (e?.message ?? '').toString();
      // Friendly mapping (kept compact compared to RecordedStrategyEditor's
      // matrix; the most common cases are concurrent-scan + worker-up).
      if (raw.includes('project_concurrent_dast_blocked')) {
        setTestError('A scan is running on this target. Cancel it to test the replay.');
      } else if (raw.includes('fly_machine_unavailable')) {
        setTestError('Worker unavailable — try again in 30 seconds.');
      } else if (raw.includes('credentials_not_set')) {
        setTestError('Save the credential first, then click Test replay.');
      } else if (raw.includes('unsupported_strategy_for_test')) {
        setTestError('This credential type is not testable.');
      } else {
        setTestError('Couldn’t start Test replay.');
      }
    } finally {
      setTesting(false);
    }
  }

  const testRunning =
    testing
    || (testJobId !== null
      && jobResult.status !== 'completed'
      && jobResult.status !== 'failed'
      && jobResult.status !== 'cancelled'
      && jobResult.status !== 'timeout'
      && jobResult.status !== 'error');
  const testResultEnvelope = jobResult.job?.error_payload ?? null;
  const testSucceeded =
    testResultEnvelope && testResultEnvelope.kind === 'test_result'
      ? testResultEnvelope.test_result.success
      : null;
  // endregion

  return (
    <div className="space-y-4">
      {!previewState && (
        <HarUploadZone
          disabled={disabled || parsing}
          parsing={parsing}
          onFile={handleFile}
        />
      )}

      {parseError && (
        <div className="flex items-start gap-2 text-xs text-destructive">
          <AlertTriangle className="h-3 w-3 mt-0.5 flex-none" />
          <span>{parseError}</span>
        </div>
      )}

      {previewState && (
        <div className="space-y-3 rounded-lg border border-border bg-background-card p-3">
          <div className="flex items-center justify-between">
            <div className="text-xs text-foreground">
              <span className="font-medium">{previewState.preview.summary.request_count}</span> requests ·{' '}
              <span className="font-medium">{previewState.preview.summary.cookies_set}</span> Set-Cookies ·{' '}
              <span className="font-medium">{previewState.preview.summary.auth_headers_observed}</span> Authorization headers
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => {
                setPreviewState(null);
                setTotpSecret('');
                setParseError(null);
              }}
              disabled={disabled}
              className="h-6 px-2 text-xs"
            >
              <X className="h-3 w-3 mr-1" /> Clear
            </Button>
          </div>
          <div className="text-xs text-foreground-secondary">
            Origins: <span className="font-mono">{previewState.preview.summary.origins.join(', ')}</span>
          </div>
          <div className="text-xs text-foreground-muted">
            Stripped {previewState.preview.summary.dropped_header_count} non-auth headers ·{' '}
            {Math.round(previewState.preview.summary.dropped_bytes / 1024)} KB telemetry · kept{' '}
            {previewState.preview.summary.kept_header_count} headers
          </div>

          {previewState.preview.non_replayable_warnings.length > 0 && (
            <div className="flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/5 p-2 text-xs text-amber-200">
              <AlertTriangle className="h-3 w-3 mt-0.5 flex-none" />
              <span>
                Detected patterns that can’t be replayed at scan time:{' '}
                {previewState.preview.non_replayable_warnings
                  .map((w) => w.pattern_hint)
                  .join(', ')}
                . Test-replay will likely fail at one of these requests.
              </span>
            </div>
          )}

          {previewState.preview.totp_detected && (
            <div className="space-y-1.5">
              <Label htmlFor="replay-totp-secret" className="text-xs text-foreground">
                TOTP secret (RFC 6238 base32 — A-Z + 2-7)
              </Label>
              <Input
                id="replay-totp-secret"
                value={totpSecret}
                onChange={(e) => setTotpSecret(e.target.value.toUpperCase())}
                disabled={disabled}
                placeholder="JBSWY3DPEHPK3PXP"
                className="font-mono text-xs"
                autoComplete="off"
              />
              <p className="text-[11px] text-foreground-muted">
                We detected a TOTP step at request #{previewState.preview.totp_detected.entry_index}.
                Paste your base32 secret so the script regenerates fresh codes on every scan
                (RFC 6238 defaults: SHA-1, 30 s, 6 digits).
              </p>
            </div>
          )}

          <div className="space-y-1.5">
            <Label htmlFor="replay-label" className="text-xs text-foreground">
              Label (optional)
            </Label>
            <Input
              id="replay-label"
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              disabled={disabled}
              placeholder="staging Auth0 tenant"
              maxLength={80}
            />
          </div>

          {/* region:test-job-state — synced pattern with RecordedStrategyEditor.tsx */}
          <div className="space-y-2 border-t border-border pt-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={runTest}
              disabled={disabled || testRunning || !payload}
              className="h-8 text-xs"
            >
              {testRunning ? (
                <>
                  <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> Testing replay…
                </>
              ) : (
                <>Test replay</>
              )}
            </Button>
            {testError && (
              <div className="flex items-start gap-2 text-xs text-destructive">
                <AlertTriangle className="h-3 w-3 mt-0.5 flex-none" />
                <span>{testError}</span>
              </div>
            )}
            {testSucceeded === true && (
              <div className="flex items-start gap-2 text-xs text-emerald-500">
                <CheckCircle2 className="h-3 w-3 mt-0.5 flex-none" />
                <span>Test replay succeeded — the captured requests authenticated against the target.</span>
              </div>
            )}
            {testSucceeded === false && (
              <div className="flex items-start gap-2 text-xs text-destructive">
                <AlertTriangle className="h-3 w-3 mt-0.5 flex-none" />
                <span>
                  Test replay failed. Common causes: stale captured tokens, the loggedIn indicator
                  doesn’t match, or a non-replayable pattern (WebAuthn / SMS) is mid-flow.
                </span>
              </div>
            )}
          </div>
          {/* endregion */}
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// HarUploadZone — drag-drop + file picker.
// ---------------------------------------------------------------------------

function HarUploadZone({
  disabled,
  parsing,
  onFile,
}: {
  disabled?: boolean;
  parsing?: boolean;
  onFile: (f: File) => void;
}) {
  const [dragging, setDragging] = useState(false);
  return (
    <label
      htmlFor="replay-har-file"
      onDragOver={(e) => {
        e.preventDefault();
        if (!disabled) setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        if (disabled) return;
        const f = e.dataTransfer.files[0];
        if (f) onFile(f);
      }}
      className={`flex flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed p-6 cursor-pointer transition-colors ${
        dragging
          ? 'border-primary bg-primary/5'
          : 'border-border bg-background-card hover:bg-table-hover'
      } ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
    >
      <input
        id="replay-har-file"
        type="file"
        accept=".har,application/json"
        disabled={disabled}
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) onFile(f);
          // Reset so re-uploading the same file fires onChange.
          e.target.value = '';
        }}
        className="hidden"
      />
      {parsing ? (
        <Loader2 className="h-5 w-5 animate-spin text-foreground-secondary" />
      ) : (
        <Upload className="h-5 w-5 text-foreground-secondary" />
      )}
      <div className="text-sm text-foreground text-center">
        Drag a <code className="font-mono text-xs">.har</code> file here, or click to choose one.
      </div>
      <div className="text-[11px] text-foreground-muted text-center max-w-md">
        Export from Chrome DevTools → Network → ⋮ → Save all as HAR with content. Capture just the
        sign-in flow (open DevTools, click Sign in, watch for the dashboard). 1.5 MB max.
      </div>
    </label>
  );
}

// ---------------------------------------------------------------------------
// Extract the ReplayedRequest list from a raw HAR for client-side hold.
// Mirrors the structural extraction the backend parser does, but skips the
// scrubbers + privacy gates (those happen server-side at preview time
// AND again at PUT time, so this is just a structural pull).
// ---------------------------------------------------------------------------

function extractRequestsFromHar(har: unknown): ReplayedRequest[] {
  if (!har || typeof har !== 'object') return [];
  const top = har as Record<string, unknown>;
  const log = (top.log && typeof top.log === 'object' ? top.log : top) as Record<string, unknown>;
  const entries = Array.isArray(log.entries) ? log.entries : [];
  const out: ReplayedRequest[] = [];
  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const e = entry as Record<string, unknown>;
    const req = (e.request && typeof e.request === 'object' ? e.request : null) as Record<string, unknown> | null;
    if (!req) continue;
    const method = typeof req.method === 'string' ? req.method.toUpperCase() : 'GET';
    const url = typeof req.url === 'string' ? req.url : '';
    if (!url) continue;
    const rawHeaders = Array.isArray(req.headers) ? req.headers : [];
    const headers: { name: string; value: string }[] = [];
    for (const h of rawHeaders) {
      if (!h || typeof h !== 'object') continue;
      const name = typeof (h as { name?: unknown }).name === 'string' ? (h as { name: string }).name : '';
      const value = typeof (h as { value?: unknown }).value === 'string' ? (h as { value: string }).value : '';
      if (name) headers.push({ name, value });
    }
    let body: string | undefined;
    if (req.postData && typeof req.postData === 'object') {
      const pd = req.postData as Record<string, unknown>;
      if (typeof pd.text === 'string') body = pd.text;
    }
    out.push({
      method,
      url,
      headers,
      ...(body !== undefined ? { body, body_encoding: 'utf8' as const } : {}),
    });
  }
  return out;
}
