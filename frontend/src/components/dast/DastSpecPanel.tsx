// Phase 35 (v1.1) — DAST OpenAPI spec config panel.
//
// Mounts inside DastTargetEditDialog as a new sibling block after the
// Authentication section (line ~241). 3 modes — synthesized (default),
// url, none. Upload mode is deferred to v1.2 and not rendered.

import { useEffect, useState } from 'react';
import { Loader2, FileCode, Download, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Button } from '../ui/button';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/select';
import { useToast } from '../../hooks/use-toast';
import {
  api,
  type DastSpecConfigDTO,
  type DastSpecSource,
  type DastTargetDTO,
} from '../../lib/api';
import { friendlySpecErrorMessage } from '../../lib/dast-error-codes';

interface DastSpecPanelProps {
  projectId: string;
  target: DastTargetDTO;
  canManage: boolean;
  /** Called with the updated target after a successful PATCH /spec. */
  onUpdated: (target: DastTargetDTO) => void;
}

function inferSoftWarnCopy(cfg: DastSpecConfigDTO): string | null {
  if (cfg.last_synthesis_ok !== false) return null;
  if (cfg.api_spec_source === 'synthesized') {
    if ((cfg.last_synthesis_endpoint_count ?? 0) === 0) {
      return 'No endpoints detected. Run a code scan first, or check that your framework is supported.';
    }
    return 'Last scan couldn’t write the spec to storage. Retry the scan; the download will work after the next successful run.';
  }
  if (cfg.api_spec_source === 'url') {
    if (!cfg.last_synthesized_at) {
      return 'URL spec fetch failed on the last scan. Retry next scan or update the URL.';
    }
    return 'URL spec changed and now fails to parse. Update the spec at its source.';
  }
  return null;
}

export function DastSpecPanel({
  projectId,
  target,
  canManage,
  onUpdated,
}: DastSpecPanelProps) {
  const { toast } = useToast();
  const cfg = target.spec_config;
  const [source, setSource] = useState<DastSpecSource>(cfg.api_spec_source);
  const [urlDraft, setUrlDraft] = useState(cfg.api_spec_url ?? '');
  const [saving, setSaving] = useState(false);
  const [downloading, setDownloading] = useState(false);

  // Reset draft state if the parent updates target (e.g. after save).
  useEffect(() => {
    setSource(cfg.api_spec_source);
    setUrlDraft(cfg.api_spec_url ?? '');
  }, [cfg.api_spec_source, cfg.api_spec_url]);

  const dirty =
    source !== cfg.api_spec_source ||
    (source === 'url' && urlDraft.trim() !== (cfg.api_spec_url ?? ''));

  const handleSave = async () => {
    if (!canManage || saving) return;
    if (source === 'url' && urlDraft.trim().length === 0) {
      toast({
        title: 'Failed to save spec config',
        description: friendlySpecErrorMessage('spec_url_required'),
        variant: 'destructive',
      });
      return;
    }
    setSaving(true);
    try {
      const updated = await api.setDastTargetSpec(projectId, target.id, {
        api_spec_source: source,
        ...(source === 'url' ? { api_spec_url: urlDraft.trim() } : {}),
      });
      onUpdated(updated);
      toast({
        title: 'Spec config updated',
        description:
          source === 'synthesized'
            ? 'Deptex will synthesize an OpenAPI spec from your code on the next scan.'
            : source === 'url'
              ? 'Spec URL validated and saved. The next scan will fetch fresh.'
              : 'Spec mode disabled. Next scan will run spider-only.',
      });
    } catch (e: any) {
      // Backend errors come back as Error.message containing the body's
      // `error` code. Try to parse; fall back to message.
      const code = String(e?.message ?? '').match(/[a-z_]+/)?.[0];
      toast({
        title: 'Failed to save spec config',
        description: friendlySpecErrorMessage(code, e?.detail),
        variant: 'destructive',
      });
    } finally {
      setSaving(false);
    }
  };

  const handleDownload = async () => {
    if (downloading) return;
    setDownloading(true);
    try {
      const link = await api.getDastTargetSpecDownload(projectId, target.id);
      if (!link) {
        toast({
          title: 'No spec available yet',
          description: friendlySpecErrorMessage('spec_unavailable'),
          variant: 'destructive',
        });
        return;
      }
      // Open in a new tab — signed URL for synthesized, direct upstream
      // URL for url mode. Either way the browser downloads/displays.
      window.open(link.url, '_blank', 'noopener,noreferrer');
    } catch (e: any) {
      toast({
        title: 'Failed to download spec',
        description: e?.message ?? 'Unknown error',
        variant: 'destructive',
      });
    } finally {
      setDownloading(false);
    }
  };

  const softWarnCopy = inferSoftWarnCopy(cfg);

  return (
    <div className="pt-2 border-t border-border">
      <h3 className="text-base font-medium text-foreground mb-1">API Specification</h3>
      <p className="text-xs text-foreground-muted mb-4">
        Choose how Deptex finds your API endpoints. Synthesized (the default)
        builds an OpenAPI spec from your code on every scan. URL fetches a
        spec you host. None falls back to spider-only crawl.
      </p>

      <div className="rounded-lg border border-border bg-background-card p-6 space-y-4">
        <div className="space-y-2">
          <Label htmlFor={`spec-source-${target.id}`} className="text-sm">
            Spec source
          </Label>
          <Select
            value={source}
            onValueChange={(v) => setSource(v as DastSpecSource)}
            disabled={!canManage || saving}
          >
            <SelectTrigger id={`spec-source-${target.id}`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="synthesized">
                Synthesized — build from code
              </SelectItem>
              <SelectItem value="url">URL — fetch from a hosted spec</SelectItem>
              <SelectItem value="none">None — spider-only</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-foreground-muted">
            {source === 'synthesized' &&
              'Deptex builds an OpenAPI spec from your code on each scan. Supported: Express, Fastify, Flask, FastAPI, Django, Spring, Gin, Rails.'}
            {source === 'url' &&
              'Deptex fetches your OpenAPI 3.0 / 3.1 or Swagger 2.0 spec on every scan. Validated when you save.'}
            {source === 'none' &&
              'Spec-driven scanning is disabled. Scans rely on spider crawl only.'}
          </p>
        </div>

        {source === 'url' && (
          <div className="space-y-2">
            <Label htmlFor={`spec-url-${target.id}`} className="text-sm">
              Spec URL
            </Label>
            <Input
              id={`spec-url-${target.id}`}
              type="url"
              value={urlDraft}
              onChange={(e) => setUrlDraft(e.target.value)}
              placeholder="https://api.example.com/openapi.yaml"
              disabled={!canManage || saving}
            />
            <p className="text-xs text-foreground-muted">
              Validated when you save. Fetched fresh on every scan; failures
              fall back to spider-only.
            </p>
          </div>
        )}

        {source === 'synthesized' && cfg.last_synthesis_ok === true && (
          <div className="flex items-center gap-2 text-xs text-foreground-secondary">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-500" />
            <span>
              Last scan synthesized {cfg.last_synthesis_endpoint_count ?? 0}{' '}
              endpoint{(cfg.last_synthesis_endpoint_count ?? 0) === 1 ? '' : 's'}
              {cfg.last_synthesized_at
                ? ` · ${new Date(cfg.last_synthesized_at).toLocaleString()}`
                : ''}
              .
            </span>
          </div>
        )}

        {source === 'synthesized' && cfg.last_synthesis_ok === null && (
          <p className="text-xs text-foreground-muted">
            No spec yet — runs at scan time.
          </p>
        )}

        {softWarnCopy && (
          <div className="flex items-start gap-2 rounded border border-amber-500/30 bg-amber-500/5 p-3 text-xs">
            <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
            <span className="text-foreground-secondary">{softWarnCopy}</span>
          </div>
        )}

        <div className="flex items-center justify-between pt-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleDownload}
            disabled={downloading || cfg.api_spec_source === 'none'}
          >
            {downloading ? (
              <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5 mr-1.5" />
            )}
            Download spec
          </Button>
          <Button
            variant="white"
            size="sm"
            onClick={handleSave}
            disabled={!canManage || saving || !dirty}
          >
            {saving ? (
              <>
                <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                Saving…
              </>
            ) : (
              <>
                <FileCode className="h-3.5 w-3.5 mr-1.5" />
                Save spec config
              </>
            )}
          </Button>
        </div>
      </div>
    </div>
  );
}
