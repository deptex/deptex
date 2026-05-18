/**
 * Base-image advisor tests — shell-presence detection, recommendation
 * generation, and the top-50 corpus coverage gate (M4 success criterion 2).
 */

import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import {
  detectShellPresence,
  generateRecommendation,
  inferLibc,
  type RecommendationInput,
} from '../base-image-advisor';

function baseInput(overrides: Partial<RecommendationInput>): RecommendationInput {
  return {
    project_id: 'proj-1',
    organization_id: 'org-1',
    extraction_run_id: 'run-1',
    dockerfile_path: 'Dockerfile',
    currentImage: 'node:20-bullseye',
    currentImageDigest: 'sha256:' + 'a'.repeat(64),
    currentImageFindingCount: 40,
    dockerfileText: 'FROM node:20-bullseye\nCMD ["node", "server.js"]\n',
    ...overrides,
  };
}

// ---- detectShellPresence ---------------------------------------------------

describe('detectShellPresence', () => {
  it('flags shell-form CMD as shell_required', () => {
    const r = detectShellPresence('FROM node:20\nCMD node server.js\n');
    expect(r.verdict).toBe('shell_required');
    expect(r.evidence.cmd_form).toBe('shell');
  });

  it('flags exec-form non-shell CMD as no_shell_required', () => {
    const r = detectShellPresence('FROM node:20\nCMD ["node", "server.js"]\n');
    expect(r.verdict).toBe('no_shell_required');
    expect(r.evidence.cmd_form).toBe('exec');
  });

  it('flags an exec-form ["sh","-c",...] entrypoint as shell_required', () => {
    const r = detectShellPresence(
      'FROM node:20\nENTRYPOINT ["sh", "-c", "node server.js && tail -f /dev/null"]\n'
    );
    expect(r.verdict).toBe('shell_required');
    expect(r.evidence.shell_interpreter).toBe(true);
  });

  it('flags a RUN in the final stage as shell_required', () => {
    const r = detectShellPresence(
      'FROM node:20\nRUN npm ci\nCMD ["node", "server.js"]\n'
    );
    expect(r.verdict).toBe('shell_required');
    expect(r.evidence.final_stage_has_run).toBe(true);
  });

  it('does not count a RUN from an earlier build stage against the final stage', () => {
    const multi =
      'FROM node:20 AS builder\nRUN npm ci\n' +
      'FROM gcr.io/distroless/nodejs20\nCOPY --from=builder /app /app\nCMD ["server.js"]\n';
    const r = detectShellPresence(multi);
    expect(r.evidence.final_stage_has_run).toBe(false);
    expect(r.verdict).toBe('no_shell_required');
  });

  it('returns unknown for an unreadable Dockerfile', () => {
    expect(detectShellPresence(null).verdict).toBe('unknown');
  });

  it('returns unknown when there is no CMD or ENTRYPOINT', () => {
    expect(detectShellPresence('FROM node:20\nCOPY . /app\n').verdict).toBe('unknown');
  });
});

// ---- inferLibc -------------------------------------------------------------

describe('inferLibc', () => {
  it('maps alpine to musl, scratch/static to none, everything else to glibc', () => {
    expect(inferLibc('node:20-alpine')).toBe('musl');
    expect(inferLibc('gcr.io/distroless/static-debian12')).toBe('none');
    expect(inferLibc('node:20-bullseye')).toBe('glibc');
  });
});

// ---- generateRecommendation ------------------------------------------------

describe('generateRecommendation', () => {
  it('recommends a hardened alternative for a Node base image', () => {
    const row = generateRecommendation(baseInput({}));
    expect(row.recommended_image).not.toBeNull();
    expect(row.recommended_image_cve_count).not.toBeNull();
    expect(row.cve_delta).toBe(40 - (row.recommended_image_cve_count ?? 0));
    expect(row.drop_in_score).toBeGreaterThan(0);
  });

  it('recommends an alternative for a Debian base image', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'debian:bookworm', dockerfileText: 'FROM debian:bookworm\nCMD ["/app/run"]\n' })
    );
    expect(row.recommended_image).not.toBeNull();
  });

  it('recommends an alternative for an Alpine base image', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'alpine:3.20', dockerfileText: 'FROM alpine:3.20\nCMD ["/app/run"]\n' })
    );
    expect(row.recommended_image).not.toBeNull();
  });

  it('returns an empty-state row when the image is not in the catalog', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'acme/internal-app:1.0', dockerfileText: 'FROM acme/internal-app:1.0\nCMD ["/app"]\n' })
    );
    expect(row.recommended_image).toBeNull();
    expect(row.recommended_image_cve_count).toBeNull();
    expect(row.cve_delta).toBeNull();
    expect(row.alternatives).toEqual([]);
    expect(row.shell_compat_evidence.no_catalog_match).toBe(true);
  });

  it('drops shell-less alternatives when the Dockerfile needs a shell', () => {
    // node:20 has chainguard + distroless (no shell) and dhi + alpine (shell).
    const row = generateRecommendation(
      baseInput({ currentImage: 'node:20', dockerfileText: 'FROM node:20\nRUN npm ci\nCMD node server.js\n' })
    );
    expect(row.shell_compat_verdict).toBe('shell_required');
    expect(row.recommended_image).not.toBeNull();
    // The picked image must be one of the shell-bearing alternatives.
    expect(row.recommended_image).not.toBe('cgr.dev/chainguard/node:20');
    expect(row.recommended_image).not.toBe('gcr.io/distroless/nodejs20-debian12');
  });

  it('returns an empty-state row when every alternative is shell-incompatible', () => {
    // golang:1.23 alternatives are both shell-less; a shell-required Dockerfile
    // filters them all out.
    const row = generateRecommendation(
      baseInput({
        currentImage: 'golang:1.23',
        dockerfileText: 'FROM golang:1.23\nRUN go build\nCMD ./app\n',
      })
    );
    expect(row.shell_compat_verdict).toBe('shell_required');
    expect(row.recommended_image).toBeNull();
    expect(row.shell_compat_evidence.all_alternatives_shell_incompatible).toBe(true);
  });

  it('persists the current image digest so inline finding pointers can join', () => {
    const digest = 'sha256:' + 'c'.repeat(64);
    const row = generateRecommendation(baseInput({ currentImageDigest: digest }));
    expect(row.current_image_digest).toBe(digest);
  });

  it('marks likely_safe when the Dockerfile needs no shell and libc matches', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'node:20-bullseye', dockerfileText: 'FROM node:20-bullseye\nCMD ["node", "x.js"]\n' })
    );
    expect(row.shell_compat_verdict).toBe('no_shell_required');
    expect(row.shell_compat_evidence.likely_safe).toBe(true);
  });

  it('does not mark likely_safe when a shell is required', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'node:20', dockerfileText: 'FROM node:20\nCMD node server.js\n' })
    );
    expect(row.shell_compat_evidence.likely_safe).toBe(false);
  });

  it('keeps up to two runner-up alternatives alongside the picked one', () => {
    const row = generateRecommendation(
      baseInput({ currentImage: 'node:20', dockerfileText: 'FROM node:20\nCMD ["node", "x.js"]\n' })
    );
    expect(row.alternatives.length).toBeLessThanOrEqual(2);
    expect(row.alternatives.every((a) => a.image !== row.recommended_image)).toBe(true);
  });
});

// ---- top-50 corpus coverage gate (M4 success criterion 2) ------------------

describe('catalog coverage', () => {
  it('produces a recommendation for at least 35 of the top-50 base images', () => {
    const corpusPath = path.join(__dirname, 'fixtures', 'base-image-top50.yaml');
    const corpus = yaml.load(fs.readFileSync(corpusPath, 'utf8')) as { images: string[] };
    expect(corpus.images.length).toBeGreaterThanOrEqual(50);

    let withRecommendation = 0;
    for (const image of corpus.images) {
      const row = generateRecommendation(
        baseInput({ currentImage: image, dockerfileText: `FROM ${image}\nCMD ["/app/run"]\n` })
      );
      if (row.recommended_image !== null) withRecommendation += 1;
    }
    expect(withRecommendation).toBeGreaterThanOrEqual(35);
  });
});
