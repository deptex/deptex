import * as fs from 'fs';
import * as path from 'path';
import { FixJobRow } from './job-db';

export type FixStrategy = FixJobRow['strategy'];

// ---------- Ecosystem detection ----------

export function detectEcosystem(repoRoot: string): string | null {
  if (fs.existsSync(path.join(repoRoot, 'package.json'))) return 'npm';
  if (fs.existsSync(path.join(repoRoot, 'requirements.txt')) || fs.existsSync(path.join(repoRoot, 'pyproject.toml'))) return 'pypi';
  if (fs.existsSync(path.join(repoRoot, 'Cargo.toml'))) return 'cargo';
  if (fs.existsSync(path.join(repoRoot, 'go.mod'))) return 'golang';
  if (fs.existsSync(path.join(repoRoot, 'pom.xml'))) return 'maven';
  if (fs.existsSync(path.join(repoRoot, 'Gemfile'))) return 'gem';
  if (fs.existsSync(path.join(repoRoot, 'composer.json'))) return 'composer';
  if (fs.existsSync(path.join(repoRoot, 'pubspec.yaml'))) return 'pub';
  if (fs.existsSync(path.join(repoRoot, 'mix.exs'))) return 'hex';
  if (fs.existsSync(path.join(repoRoot, 'Package.swift'))) return 'swift';
  try {
    const files = fs.readdirSync(repoRoot);
    if (files.some(f => f.endsWith('.csproj'))) return 'nuget';
  } catch { /* ignore */ }
  return null;
}

// ---------- File mapping ----------

const MANIFEST_MAP: Record<string, string[]> = {
  npm: ['package.json', 'package-lock.json'],
  yarn: ['package.json', 'yarn.lock'],
  pnpm: ['package.json', 'pnpm-lock.yaml'],
  pypi: ['requirements.txt', 'pyproject.toml', 'poetry.lock'],
  cargo: ['Cargo.toml', 'Cargo.lock'],
  golang: ['go.mod', 'go.sum'],
  maven: ['pom.xml'],
  gem: ['Gemfile', 'Gemfile.lock'],
  composer: ['composer.json', 'composer.lock'],
  pub: ['pubspec.yaml', 'pubspec.lock'],
  hex: ['mix.exs', 'mix.lock'],
  swift: ['Package.swift', 'Package.resolved'],
  nuget: [],
};

export function getStrategyFiles(ecosystem: string, rootDir: string): string[] {
  const candidates = MANIFEST_MAP[ecosystem] ?? [];
  const existing = candidates
    .map(f => path.join(rootDir, f))
    .filter(f => fs.existsSync(f));

  if (ecosystem === 'nuget') {
    try {
      const files = fs.readdirSync(rootDir);
      const csprojs = files.filter(f => f.endsWith('.csproj')).map(f => path.join(rootDir, f));
      existing.push(...csprojs);
    } catch { /* ignore */ }
  }

  return existing;
}

// ---------- Override mechanisms ----------

const OVERRIDE_INSTRUCTIONS: Record<string, string> = {
  npm: 'Add to "overrides" in package.json',
  yarn: 'Add to "resolutions" in package.json',
  pnpm: 'Add to "pnpm.overrides" in package.json',
  pypi: 'Add a constraint in requirements.txt or constraints.txt',
  cargo: 'Add a [patch.crates-io] section in Cargo.toml',
  golang: 'Add a "replace" directive in go.mod',
  maven: 'Add to <dependencyManagement> in pom.xml',
  gem: 'Pin the exact version in the Gemfile',
  composer: 'Pin the exact version constraint in composer.json',
  pub: 'Add to "dependency_overrides" in pubspec.yaml',
  hex: 'Override in mix.exs',
  swift: 'Pin the exact version in Package.swift',
  nuget: 'Pin the exact version in the .csproj file',
};

// ---------- Env var patterns ----------

const ENV_VAR_PATTERNS: Record<string, string> = {
  npm: 'process.env.{ENV_VAR_NAME}',
  pypi: "os.environ['{ENV_VAR_NAME}']",
  golang: 'os.Getenv("{ENV_VAR_NAME}")',
  maven: 'System.getenv("{ENV_VAR_NAME}")',
  gem: "ENV['{ENV_VAR_NAME}']",
  cargo: 'std::env::var("{ENV_VAR_NAME}")',
};

// ---------- Prompt builders ----------

export function buildFixPrompt(job: FixJobRow, ecosystem: string): string {
  const p = job.payload;
  switch (job.strategy) {
    case 'bump_version':
      return buildBumpVersionPrompt(job, ecosystem, p);
    case 'code_patch':
      return buildCodePatchPrompt(job, ecosystem, p);
    case 'add_wrapper':
      return buildAddWrapperPrompt(job, ecosystem, p);
    case 'pin_transitive':
      return buildPinTransitivePrompt(job, ecosystem, p);
    case 'remove_unused':
      return buildRemoveUnusedPrompt(job, ecosystem, p);
    case 'fix_semgrep':
      return buildFixSemgrepPrompt(job, p);
    case 'remediate_secret':
      return buildRemediateSecretPrompt(job, ecosystem, p);
    default:
      return `Fix the security issue in this ${ecosystem} project.`;
  }
}

function buildBumpVersionPrompt(job: FixJobRow, eco: string, p: any): string {
  const depName = p.dependency?.name ?? 'the dependency';
  const curVer = p.dependency?.currentVersion ?? 'current';
  const targetVer = job.target_version ?? p.dependency?.latestVersion ?? 'latest safe';
  const osvId = job.osv_id ?? 'a known vulnerability';

  let prompt = `Upgrade ${depName} from ${curVer} to ${targetVer} to fix ${osvId}.\n`;
  prompt += `Update the package manifest and lockfile for this ${eco} project.\n`;
  prompt += `If there are breaking changes between these versions, make necessary code adjustments.\n\n`;

  if (p.usageSlices?.length) {
    prompt += `CONTEXT - How this package is used in the project:\n`;
    for (const s of p.usageSlices.slice(0, 10)) {
      prompt += `  ${s.file_path}:${s.line_number} — ${s.target_name}()\n`;
    }
    prompt += '\n';
  }

  if (p.reachableFlows?.length) {
    const flow = p.reachableFlows[0];
    prompt += `CONTEXT - Reachable data flow:\n`;
    prompt += `  Entry: ${flow.entry_point_file}:${flow.entry_point_line} (${flow.entry_point_method})\n`;
    prompt += `  Sink: ${flow.sink_method}\n`;
    if (flow.llm_prompt) prompt += `\nCONTEXT - dep-scan analysis:\n${flow.llm_prompt}\n`;
    prompt += '\n';
  }

  prompt += `After upgrading, verify the usage sites above still work correctly.\nDo NOT change any unrelated files.`;
  return prompt;
}

function buildCodePatchPrompt(job: FixJobRow, eco: string, p: any): string {
  const depName = p.dependency?.name ?? 'the dependency';
  const version = p.dependency?.currentVersion ?? '';
  const vuln = p.vulnerability;

  let prompt = `The dependency ${depName}@${version} has vulnerability ${job.osv_id}: ${vuln?.summary ?? 'see details'}.\n`;
  prompt += `No fixed version is available. Add mitigation at the application level.\n\n`;

  if (p.reachableFlows?.length) {
    const flow = p.reachableFlows[0];
    prompt += `REACHABLE DATA FLOW (from static analysis):\n`;
    prompt += `Entry point: ${flow.entry_point_file}:${flow.entry_point_line} (${flow.entry_point_method})\n`;
    prompt += `Sink: ${flow.sink_method} in ${depName}\n\n`;
    if (flow.llm_prompt) prompt += `Analysis:\n${flow.llm_prompt}\n\n`;
  }

  prompt += `Add input validation, sanitization, or a safe wrapper at or before the vulnerable call.\nExplain what you changed and why.`;
  return prompt;
}

function buildAddWrapperPrompt(job: FixJobRow, eco: string, p: any): string {
  const depName = p.dependency?.name ?? 'the dependency';
  const version = p.dependency?.currentVersion ?? '';

  let prompt = `A vulnerable function in ${depName}@${version} has ${job.osv_id}.\n`;
  if (p.importedFunctions?.length) {
    prompt += `Your code calls these functions:\n`;
    for (const fn of p.importedFunctions.slice(0, 10)) {
      prompt += `  ${fn.function_name} (${fn.import_type})\n`;
    }
  }
  if (p.importingFiles?.length) {
    prompt += `Used in files:\n`;
    for (const f of p.importingFiles.slice(0, 10)) {
      prompt += `  ${f}\n`;
    }
  }
  prompt += `\nCreate a safe wrapper function that sanitizes input before calling the vulnerable function,`;
  prompt += ` then update all call sites to use the wrapper.`;
  return prompt;
}

function buildPinTransitivePrompt(job: FixJobRow, eco: string, p: any): string {
  const depName = p.dependency?.name ?? 'the dependency';
  const curVer = p.dependency?.currentVersion ?? 'current';
  const safeVer = job.target_version ?? 'the latest safe version';
  const instruction = OVERRIDE_INSTRUCTIONS[eco] ?? 'Pin the exact version in the manifest file';

  return `The transitive dependency ${depName}@${curVer} has vulnerability ${job.osv_id}.\n` +
    `Pin it to ${safeVer} using the ${eco} override mechanism:\n${instruction}\n` +
    `Do NOT change any unrelated files.`;
}

function buildRemoveUnusedPrompt(job: FixJobRow, eco: string, p: any): string {
  const depName = p.dependency?.name ?? 'the dependency';
  return `Remove the unused dependency ${depName} from this ${eco} project.\n` +
    `Usage analysis confirms no code in this project imports or calls any function from this package.\n` +
    `Remove it from the package manifest and lockfile.\n` +
    `Remove any remaining import statements that reference it.\nDo NOT change any unrelated files.`;
}

function buildFixSemgrepPrompt(job: FixJobRow, p: any): string {
  const f = p.semgrepFinding;
  if (!f) return 'Fix the Semgrep security finding in this project.';

  return `Fix the security issue found by Semgrep rule ${f.rule_id} at ${f.path}:${f.line_start}-${f.line_end}.\n` +
    `Category: ${f.category ?? 'security'}\nSeverity: ${f.severity}\n` +
    (f.cwe_ids ? `CWE: ${f.cwe_ids}\n` : '') +
    `Message: ${f.message}\n\n` +
    `Fix the vulnerability while preserving the existing functionality.\nFollow OWASP best practices for this category of issue.`;
}

function buildRemediateSecretPrompt(job: FixJobRow, eco: string, p: any): string {
  const s = p.secretFinding;
  if (!s) return 'Replace the hardcoded secret with an environment variable.';

  const envPattern = ENV_VAR_PATTERNS[eco] ?? 'process.env.{ENV_VAR_NAME}';

  return `An exposed ${s.detector_type} secret was found at ${s.file_path}:${s.line_number}.\n` +
    `Replace the hardcoded secret value with an environment variable reference.\n` +
    `Use the pattern: ${envPattern}\n\n` +
    `Add a comment noting the env var that needs to be set.\n` +
    `If a .env.example file exists, add the variable name there (without the value).\n` +
    `Do NOT include the actual secret value anywhere in the code.`;
}

// ---------- Audit/Install commands ----------

export function getSafeInstallCommand(ecosystem: string): string | null {
  const cmds: Record<string, string> = {
    npm: 'npm install --ignore-scripts',
    yarn: 'yarn install --ignore-scripts',
    pnpm: 'pnpm install --ignore-scripts',
    pypi: 'pip install --no-deps -r requirements.txt',
    cargo: 'cargo check',
    golang: 'go mod tidy',
    maven: 'mvn compile -q',
    gem: 'bundle install --no-install',
    composer: 'composer install --no-scripts',
    pub: 'dart pub get',
    hex: 'mix deps.get',
    swift: 'swift package resolve',
    nuget: 'dotnet restore',
  };
  return cmds[ecosystem] ?? null;
}

export function getAuditCommand(ecosystem: string): string | null {
  const cmds: Record<string, string> = {
    npm: 'npm audit --json',
    yarn: 'yarn audit --json',
    pnpm: 'pnpm audit --json',
    pypi: 'pip-audit --format=json',
    cargo: 'cargo audit --json',
    golang: 'govulncheck -json ./...',
    maven: 'mvn org.owasp:dependency-check-maven:check',
    gem: 'bundle-audit check',
    composer: 'composer audit --format=json',
  };
  return cmds[ecosystem] ?? null;
}

export function getTestCommand(ecosystem: string, workDir: string): string | null {
  if (ecosystem === 'npm' || ecosystem === 'yarn' || ecosystem === 'pnpm') {
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(workDir, 'package.json'), 'utf-8'));
      if (pkg.scripts?.test && pkg.scripts.test !== 'echo "Error: no test specified" && exit 1') {
        return ecosystem === 'npm' ? 'npm test' : ecosystem === 'yarn' ? 'yarn test' : 'pnpm test';
      }
    } catch { /* no package.json */ }
    return null;
  }
  const cmds: Record<string, string> = {
    pypi: 'python -m pytest --timeout=120 -x',
    cargo: 'cargo test',
    golang: 'go test ./...',
    maven: 'mvn test -q',
    gem: 'bundle exec rake test',
    composer: 'composer test',
    pub: 'dart test',
    hex: 'mix test',
    nuget: 'dotnet test',
  };
  return cmds[ecosystem] ?? null;
}
