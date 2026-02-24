/** Manifest filename -> ecosystem id (also the PURL type and depscan -t value). */
export const MANIFEST_FILES: Record<string, string> = {
  'package.json': 'npm',
  'requirements.txt': 'pypi',
  'Pipfile': 'pypi',
  'pyproject.toml': 'pypi',
  'setup.py': 'pypi',
  'pom.xml': 'maven',
  'build.gradle': 'maven',
  'build.gradle.kts': 'maven',
  'go.mod': 'golang',
  'Cargo.toml': 'cargo',
  'Gemfile': 'gem',
  'composer.json': 'composer',
  'pubspec.yaml': 'pub',
  'mix.exs': 'hex',
  'Package.swift': 'swift',
};

/** Framework detection rules per ecosystem. First match wins. */
export const FRAMEWORK_RULES: Record<string, Array<{ match: string; framework: string }>> = {
  npm: [
    { match: '"next"', framework: 'nextjs' },
    { match: '"react-scripts"', framework: 'create-react-app' },
    { match: '"react"', framework: 'react' },
    { match: '"vue"', framework: 'vue' },
    { match: '"nuxt"', framework: 'nuxt' },
    { match: '"svelte"', framework: 'svelte' },
    { match: '"@angular/core"', framework: 'angular' },
    { match: '"express"', framework: 'express' },
  ],
  pypi: [
    { match: 'django', framework: 'django' },
    { match: 'fastapi', framework: 'fastapi' },
    { match: 'flask', framework: 'flask' },
    { match: 'scrapy', framework: 'scrapy' },
  ],
  maven: [
    { match: 'spring-boot', framework: 'spring-boot' },
    { match: 'quarkus', framework: 'quarkus' },
    { match: 'android', framework: 'android' },
  ],
  golang: [
    { match: 'gin-gonic', framework: 'gin' },
    { match: 'labstack/echo', framework: 'echo' },
    { match: 'gofiber', framework: 'fiber' },
  ],
  cargo: [
    { match: 'actix', framework: 'actix' },
    { match: 'axum', framework: 'axum' },
    { match: 'rocket', framework: 'rocket' },
  ],
  gem: [
    { match: 'rails', framework: 'rails' },
    { match: 'sinatra', framework: 'sinatra' },
  ],
  nuget: [
    { match: 'Microsoft.AspNetCore', framework: 'aspnet' },
  ],
  composer: [
    { match: 'laravel', framework: 'laravel' },
    { match: 'symfony', framework: 'symfony' },
    { match: 'wordpress', framework: 'wordpress' },
  ],
};

/** Fallback framework id when no rule matches (used for icon + label). */
export const ECOSYSTEM_DEFAULTS: Record<string, string> = {
  npm: 'node',
  pypi: 'python',
  maven: 'java',
  nuget: 'dotnet',
  golang: 'go',
  cargo: 'rust',
  gem: 'ruby',
  composer: 'php',
  pub: 'dart',
  hex: 'elixir',
  swift: 'swift',
};

/** File-extension -> ecosystem id, for manifests with variable names (e.g. MyApp.csproj). */
export const MANIFEST_EXTENSIONS: Record<string, string> = {
  '.csproj': 'nuget',
  '.fsproj': 'nuget',
  '.vbproj': 'nuget',
};

/** Directories to skip when scanning repository trees for manifests. */
export const IGNORED_DIRS = [
  'node_modules', 'vendor', '.venv', 'venv', '__pycache__',
  'target', 'build', 'dist', '.git', '.next', '.nuxt',
];

/** Detect framework from manifest content using the rule tables above. */
export function detectFrameworkForEcosystem(ecosystem: string, manifestContent: string): string {
  const rules = FRAMEWORK_RULES[ecosystem] || [];
  for (const rule of rules) {
    if (manifestContent.includes(rule.match)) return rule.framework;
  }
  return ECOSYSTEM_DEFAULTS[ecosystem] || 'unknown';
}
