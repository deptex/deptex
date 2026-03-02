import express, { Request, Response } from 'express';

const router = express.Router();

// ---------------------------------------------------------------------------
// In-memory rate limiter – 20 requests per IP per hour
// ---------------------------------------------------------------------------
const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 20;
const ipHits = new Map<string, { count: number; resetAt: number }>();

function isRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = ipHits.get(ip);

  if (!entry || now > entry.resetAt) {
    ipHits.set(ip, { count: 1, resetAt: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }

  entry.count++;
  return entry.count > RATE_LIMIT_MAX;
}

// Periodically prune expired entries so the map doesn't grow unbounded
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of ipHits) {
    if (now > entry.resetAt) ipHits.delete(ip);
  }
}, RATE_LIMIT_WINDOW_MS);

// ---------------------------------------------------------------------------
// Hard-coded documentation context (topic summaries per page)
// ---------------------------------------------------------------------------
const DOCS_CONTEXT = `
Deptex Documentation Summary
=============================

## Introduction (slug: introduction)
Deptex is a dependency security and compliance platform. It helps engineering
teams monitor open-source dependencies, track known vulnerabilities (CVEs),
enforce license compliance policies, and generate SBOMs. Key value props:
automated vulnerability detection, policy enforcement, SBOM generation,
and team-based access control.

## Quick Start (slug: quick-start)
Guide to getting started: create an organization, connect a GitHub repository,
import your first project, and view the dependency graph. Covers initial setup,
GitHub App installation, first scan trigger, and interpreting the dashboard.

## Projects (slug: projects)
Projects map 1-to-1 with repositories. Each project tracks its dependency
manifest files (package.json, go.mod, requirements.txt, etc.), scan history,
vulnerability counts, compliance status, and SBOM artifacts. Projects belong
to an organization and can be assigned to teams.

## Dependencies (slug: dependencies)
Deptex resolves transitive dependency trees from manifest and lock files.
The Dependencies tab shows direct vs transitive deps, version info, license,
known CVE counts, and freshness. Supports npm, PyPI, Go modules, Maven,
Cargo, and NuGet ecosystems.

## Vulnerabilities (slug: vulnerabilities)
Vulnerabilities are sourced from the GitHub Advisory Database and NVD.
Each vulnerability shows CVE ID, severity (CVSS), affected versions, fix
availability, and impacted projects. Supports filtering by severity, status
(open/resolved/ignored), and ecosystem.

## Compliance (slug: compliance)
Compliance frameworks let organizations define acceptable license categories
and vulnerability thresholds. A project is compliant when all its dependencies
meet the active policy. Compliance status is shown per-project and org-wide.

## SBOM Compliance (slug: sbom-compliance)
Software Bill of Materials generation in CycloneDX and SPDX formats.
Tracks SBOM freshness, allows export/download, and validates completeness.
Required for supply-chain security standards (EO 14028, NIST SSDF).

## Organizations (slug: organizations)
Organizations are the top-level entity. Org settings cover billing, member
management, roles & permissions, integrations, notification rules, and
security policies. Owners can transfer or delete organizations.

## Teams (slug: teams)
Teams provide scoped visibility into projects. Members can belong to multiple
teams. Team admins manage membership. Projects can be assigned to one or
more teams to control who sees what.

## Policies (slug: policies)
Security and compliance policies are configurable rules: license allow/deny
lists, severity thresholds for blocking, auto-ignore rules, and exception
workflows. Policies can be org-wide or per-project.

## Integrations (slug: integrations)
Deptex integrates with GitHub (App + webhooks), Slack (notifications),
and CI/CD pipelines. The GitHub integration enables automatic PR checks,
scan-on-push, and repository syncing.

## Notification Rules (slug: notification-rules)
Configure automated alerts triggered by events: new critical vulnerability,
compliance status change, scan failure, etc. Delivery channels include
in-app, email, and Slack. Rules support filters by severity, project, and team.

## Terms of Service (slug: terms)
Legal terms governing use of the Deptex platform.

## Privacy Policy (slug: privacy)
How Deptex collects, uses, stores, and protects user data.

## Security (slug: security)
Deptex security practices: encryption at rest and in transit, SOC 2 alignment,
vulnerability disclosure program, and infrastructure overview.
`.trim();

const DOC_PAGES: { slug: string; title: string }[] = [
  { slug: 'introduction', title: 'Introduction' },
  { slug: 'quick-start', title: 'Quick Start' },
  { slug: 'projects', title: 'Projects' },
  { slug: 'dependencies', title: 'Dependencies' },
  { slug: 'vulnerabilities', title: 'Vulnerabilities' },
  { slug: 'compliance', title: 'Compliance' },
  { slug: 'sbom-compliance', title: 'SBOM Compliance' },
  { slug: 'organizations', title: 'Organizations' },
  { slug: 'teams', title: 'Teams' },
  { slug: 'policies', title: 'Policies' },
  { slug: 'integrations', title: 'Integrations' },
  { slug: 'notification-rules', title: 'Notification Rules' },
  { slug: 'terms', title: 'Terms of Service' },
  { slug: 'privacy', title: 'Privacy Policy' },
  { slug: 'security', title: 'Security' },
];

const SYSTEM_PROMPT =
  'You are a helpful documentation assistant for Deptex, a dependency security ' +
  'and compliance platform. Answer questions based only on the documentation ' +
  'context provided. Be concise and accurate. If you don\'t know the answer, ' +
  'say so. Include which documentation page(s) are most relevant.';

const MAX_QUESTION_LENGTH = 500;
const API_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// POST /api/docs-assistant
// ---------------------------------------------------------------------------
router.post('/', async (req: Request, res: Response) => {
  try {
    const apiKey = process.env.GOOGLE_AI_API_KEY;
    if (!apiKey) {
      return res.status(200).json({
        answer:
          'The AI documentation assistant is not configured yet. ' +
          'Please browse the documentation pages directly for answers.',
        sources: [],
      });
    }

    const ip =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';

    if (isRateLimited(ip)) {
      return res.status(429).json({
        error: 'Too many requests. Please try again later.',
      });
    }

    const { question, currentPage } = req.body as {
      question?: string;
      currentPage?: string;
    };

    if (!question || typeof question !== 'string' || !question.trim()) {
      return res.status(400).json({ error: 'A question is required.' });
    }

    if (question.length > MAX_QUESTION_LENGTH) {
      return res.status(400).json({
        error: `Question must be ${MAX_QUESTION_LENGTH} characters or fewer.`,
      });
    }

    const userPrompt = [
      `Documentation context:\n${DOCS_CONTEXT}`,
      currentPage ? `The user is currently viewing the "${currentPage}" page.` : '',
      `User question: ${question.trim()}`,
      'Respond in markdown. At the end, list the most relevant doc page slugs in a JSON array like ["slug1","slug2"].',
    ]
      .filter(Boolean)
      .join('\n\n');

    const body = {
      contents: [{ parts: [{ text: userPrompt }] }],
      systemInstruction: { parts: [{ text: SYSTEM_PROMPT }] },
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 1024,
      },
    };

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), API_TIMEOUT_MS);

    const apiUrl =
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;

    const response = await fetch(apiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    clearTimeout(timeout);

    if (!response.ok) {
      const errText = await response.text().catch(() => 'unknown error');
      console.error('Gemini API error:', response.status, errText);
      return res.status(502).json({ error: 'Failed to get a response from the AI service.' });
    }

    const data = (await response.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
    };
    const rawText: string =
      data?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';

    const { answer, sources } = parseResponse(rawText);

    return res.json({ answer, sources });
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return res.status(504).json({ error: 'AI service timed out. Please try again.' });
    }
    console.error('docs-assistant error:', err);
    return res.status(500).json({ error: 'Something went wrong. Please try again later.' });
  }
});

// ---------------------------------------------------------------------------
// Parse the model response to extract markdown answer and source slugs
// ---------------------------------------------------------------------------
function parseResponse(raw: string): {
  answer: string;
  sources: { slug: string; title: string }[];
} {
  const slugLookup = new Map(DOC_PAGES.map((p) => [p.slug, p.title]));

  // Try to extract a JSON array of slugs from the tail of the response
  const jsonMatch = raw.match(/\[[\s\S]*?\]\s*$/);
  let detectedSlugs: string[] = [];

  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[0]);
      if (Array.isArray(parsed)) {
        detectedSlugs = parsed.filter((s): s is string => typeof s === 'string');
      }
    } catch {
      // ignore – fall back to keyword matching
    }
  }

  // Remove the trailing JSON array from the visible answer
  let answer = jsonMatch ? raw.slice(0, jsonMatch.index).trim() : raw.trim();
  if (!answer) answer = raw.trim();

  // If the model didn't return slugs, infer from mentions in the answer
  if (detectedSlugs.length === 0) {
    for (const page of DOC_PAGES) {
      if (
        answer.toLowerCase().includes(page.slug) ||
        answer.toLowerCase().includes(page.title.toLowerCase())
      ) {
        detectedSlugs.push(page.slug);
      }
    }
  }

  const sources = detectedSlugs
    .filter((s) => slugLookup.has(s))
    .map((s) => ({ slug: s, title: slugLookup.get(s)! }));

  return { answer, sources };
}

export default router;
