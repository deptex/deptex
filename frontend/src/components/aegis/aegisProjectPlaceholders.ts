/** Segments for Aegis assistant markdown with inline project / team / member embeds. */
export type AegisMarkdownSegment =
  | { type: 'text'; value: string }
  | { type: 'project'; id: string }
  | { type: 'team'; id: string }
  | { type: 'member'; id: string }
  | { type: 'members_group'; ids: string[] }
  | { type: 'embed_invalid'; tag: 'project' | 'team' | 'member'; rawInner: string };

/** Standard UUID hex (Deptex Postgres ids): only 0-9 / a–f plus hyphens. */
const UUID_HEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function normalizeAegisEmbedUuid(raw: string): string | null {
  const t = raw.trim();
  return UUID_HEX.test(t) ? t.toLowerCase() : null;
}

function indexOfInsensitive(haystack: string, needle: string, from: number): number {
  return haystack.toLowerCase().indexOf(needle.toLowerCase(), from);
}

type ParsedEmbed = {
  segment: Exclude<AegisMarkdownSegment, { type: 'text' }>;
  len: number;
};

function tryParseEmbedFromChunk(
  chunk: string,
  kind: 'project' | 'team' | 'member',
): ParsedEmbed | null {
  const selfClose = new RegExp(
    `^<${kind}\\s+id\\s*=\\s*(?:'([^']*)'|"([^"]*)")\\s*\\/>`,
    'i',
  );
  const paired = new RegExp(`^<${kind}>\\s*([\\s\\S]*?)<\\/${kind}>`, 'i');

  let m = chunk.match(selfClose);
  if (m) {
    const raw = (m[1] ?? m[2] ?? '').trim();
    const id = normalizeAegisEmbedUuid(raw);
    return {
      segment: id
        ? { type: kind, id }
        : { type: 'embed_invalid', tag: kind, rawInner: truncateRaw(raw) },
      len: m[0].length,
    };
  }
  m = chunk.match(paired);
  if (m) {
    const raw = (m[1] ?? '').trim();
    const id = normalizeAegisEmbedUuid(raw);
    return {
      segment: id
        ? { type: kind, id }
        : { type: 'embed_invalid', tag: kind, rawInner: truncateRaw(raw) },
      len: m[0].length,
    };
  }
  return null;
}

function truncateRaw(s: string, max = 120): string {
  const t = s.replace(/\s+/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max)}…` : t;
}

function mergeAdjacentTextSegments(segments: AegisMarkdownSegment[]): AegisMarkdownSegment[] {
  const out: AegisMarkdownSegment[] = [];
  for (const s of segments) {
    const last = out[out.length - 1];
    if (s.type === 'text' && last?.type === 'text') {
      last.value += s.value;
    } else {
      out.push(s);
    }
  }
  return out;
}

/**
 * Returns true for the kind of trivial connectors the model writes between
 * member embeds when it's listing them: whitespace, commas, semicolons,
 * periods, the word "and", or any combination. Anything with substantive
 * prose between two embeds (e.g. "the owner is X. The team lead is Y")
 * should *not* match — those describe different things and should not group.
 */
function isMemberJoiner(text: string): boolean {
  return /^[\s,;.]*(?:and[\s,;.]*)?$/i.test(text);
}

/**
 * Collapse runs of `member` segments separated only by trivial connectors
 * (whitespace, commas, "and", …) into a single `members_group` so they render
 * as one table instead of stacked cards. A single isolated `<member>` is left
 * alone — the card surface is fine for "who is the owner of this org?" answers.
 */
function groupAdjacentMembers(segs: AegisMarkdownSegment[]): AegisMarkdownSegment[] {
  const out: AegisMarkdownSegment[] = [];
  let i = 0;
  while (i < segs.length) {
    const seg = segs[i];
    if (seg.type !== 'member') {
      out.push(seg);
      i++;
      continue;
    }
    const ids: string[] = [seg.id];
    let last = i;
    let j = i + 1;
    while (j < segs.length) {
      const next = segs[j];
      if (next.type === 'member') {
        ids.push(next.id);
        last = j;
        j++;
        continue;
      }
      if (
        next.type === 'text' &&
        isMemberJoiner(next.value) &&
        j + 1 < segs.length &&
        segs[j + 1].type === 'member'
      ) {
        j++;
        continue;
      }
      break;
    }
    if (ids.length >= 2) {
      out.push({ type: 'members_group', ids });
      i = last + 1;
    } else {
      out.push(seg);
      i++;
    }
  }
  return out;
}

/**
 * Split markdown into text plus `project` / `team` segments.
 * Loose tag matching — invalid IDs become `embed_invalid` so UI can explain instead of echoing opaque tags.
 */
export function splitAegisEmbedSegments(markdown: string): AegisMarkdownSegment[] {
  const segments: AegisMarkdownSegment[] = [];
  let pos = 0;
  while (pos < markdown.length) {
    const allCandidates: Array<{ idx: number; kind: 'project' | 'team' | 'member' }> = [
      { idx: indexOfInsensitive(markdown, '<project', pos), kind: 'project' },
      { idx: indexOfInsensitive(markdown, '<team', pos), kind: 'team' },
      { idx: indexOfInsensitive(markdown, '<member', pos), kind: 'member' },
    ];
    const candidates = allCandidates.filter((c) => c.idx >= 0);

    let next = -1;
    let kind: 'project' | 'team' | 'member' | null = null;
    if (candidates.length > 0) {
      candidates.sort((a, b) => a.idx - b.idx);
      next = candidates[0].idx;
      kind = candidates[0].kind;
    }

    if (kind === null || next < 0) {
      const tail = markdown.slice(pos);
      if (tail) segments.push({ type: 'text', value: tail });
      break;
    }

    const chunk = markdown.slice(next);
    const parsed = tryParseEmbedFromChunk(chunk, kind);
    if (!parsed) {
      if (next > pos) {
        segments.push({ type: 'text', value: markdown.slice(pos, next) });
      }
      segments.push({ type: 'text', value: markdown.slice(next, next + 1) });
      pos = next + 1;
      continue;
    }

    // Models sometimes wrap an embed tag in inline formatting — e.g.
    // `**Project:** \`<project>id</project>\`` — which leaves orphaned
    // backtick/asterisk markers rendering literally on either side of the
    // card. When the same wrapper run appears immediately before AND after
    // the tag, consume both sides along with the embed.
    let preText = markdown.slice(pos, next);
    let afterEnd = next + parsed.len;
    const wrapMatch = preText.match(/[`*_~]+$/);
    if (wrapMatch && markdown.startsWith(wrapMatch[0], afterEnd)) {
      preText = preText.slice(0, -wrapMatch[0].length);
      afterEnd += wrapMatch[0].length;
    }
    if (preText) {
      segments.push({ type: 'text', value: preText });
    }

    segments.push(parsed.segment);
    pos = afterEnd;
  }

  return groupAdjacentMembers(mergeAdjacentTextSegments(segments));
}

/** @deprecated Prefer `splitAegisEmbedSegments` */
export function splitAegisProjectSegments(markdown: string): AegisMarkdownSegment[] {
  return splitAegisEmbedSegments(markdown);
}
