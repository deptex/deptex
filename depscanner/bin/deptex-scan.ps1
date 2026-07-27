# deptex-scan.ps1 — PowerShell wrapper for the local extraction CLI.
#
# Mirrors bin/deptex-scan (bash) for users on PowerShell / cmd. See that file
# for the authoritative design notes.
#
# Usage:
#   .\bin\deptex-scan.ps1 run <path> [options]
#   .\bin\deptex-scan.ps1 --help

$ErrorActionPreference = 'Stop'

$Image = if ($env:DEPTEX_CLI_IMAGE) { $env:DEPTEX_CLI_IMAGE } else { 'deptex-cli:local' }

# Check Docker daemon is up.
& docker info *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Error "Docker daemon is not running. Start Docker Desktop and retry."
  exit 2
}

# Check image exists locally.
& docker image inspect $Image *> $null
if ($LASTEXITCODE -ne 0) {
  Write-Error "Image '$Image' not found. Build with 'npm run docker:build' or set DEPTEX_CLI_IMAGE."
  exit 2
}

# Anything other than `run <path>` passes through verbatim.
if ($args.Count -eq 0 -or $args[0] -ne 'run') {
  docker run --rm -i $Image node /app/dist/cli/index.js @args
  exit $LASTEXITCODE
}

if ($args.Count -lt 2) {
  Write-Error "missing <path> after 'run'"
  Write-Host "usage: deptex-scan.ps1 run <path> [options]"
  exit 2
}

$WorkspacePath = $args[1]
if (-not (Test-Path $WorkspacePath -PathType Container)) {
  Write-Error "workspace path '$WorkspacePath' is not a directory"
  exit 2
}

$AbsWs = (Resolve-Path $WorkspacePath).Path

# Extract --output + default --label to host basename. Accept both equals form
# (--output=./path) and space form (--output ./path) — see bin/deptex-scan for
# why the space form matters.
$OutputDir = './extraction-results'
$HasLabel = $false
$Passthrough = @()
$Rest = $args[2..($args.Count - 1)]
$i = 0
while ($i -lt $Rest.Count) {
  $arg = $Rest[$i]
  if ($arg -like '--output=*') {
    $OutputDir = $arg.Substring('--output='.Length)
  } elseif ($arg -eq '--output') {
    $i++
    if ($i -ge $Rest.Count) {
      Write-Error '--output requires a value'
      exit 2
    }
    $OutputDir = $Rest[$i]
  } elseif ($arg -like '--label=*') {
    $HasLabel = $true
    $Passthrough += $arg
  } elseif ($arg -eq '--label') {
    $i++
    if ($i -ge $Rest.Count) {
      Write-Error '--label requires a value'
      exit 2
    }
    $HasLabel = $true
    $Passthrough += "--label=$($Rest[$i])"
  } else {
    $Passthrough += $arg
  }
  $i++
}

if (-not $HasLabel) {
  $Passthrough += "--label=$((Split-Path $AbsWs -Leaf))"
}

if (-not (Test-Path $OutputDir)) {
  New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
$AbsOut = (Resolve-Path $OutputDir).Path

# Mirror bin/deptex-scan env-var forwarding. DEPTEX_LOCAL_CLI=1 is the
# gate epd.ts uses to allow ANTHROPIC_API_KEY to be picked up from the
# environment. Secret-bearing vars use the `-e VAR` (no =value) form so
# the secret never lands on docker's argv (visible via process listings
# and audit logs); non-secret config knobs use the `-e VAR=value` form.
# This list must stay at parity with bin/deptex-scan (bash wrapper).
$EnvFlags = @('-e', 'DEPTEX_LOCAL_CLI=1')

# AI provider — Anthropic.
if ($env:ANTHROPIC_API_KEY) { $EnvFlags += @('-e', 'ANTHROPIC_API_KEY') }
if ($env:ANTHROPIC_MODEL) { $EnvFlags += @('-e', "ANTHROPIC_MODEL=$($env:ANTHROPIC_MODEL)") }

# EPD budget knobs.
if ($env:EPD_MAX_RUN_COST_USD) { $EnvFlags += @('-e', "EPD_MAX_RUN_COST_USD=$($env:EPD_MAX_RUN_COST_USD)") }
if ($env:EPD_BUDGET_EXCEEDED_BEHAVIOR) { $EnvFlags += @('-e', "EPD_BUDGET_EXCEEDED_BEHAVIOR=$($env:EPD_BUDGET_EXCEEDED_BEHAVIOR)") }
if ($env:EPD_MAX_VULNS_PER_RUN) { $EnvFlags += @('-e', "EPD_MAX_VULNS_PER_RUN=$($env:EPD_MAX_VULNS_PER_RUN)") }

# Phase 5 per-org AI rule generation knobs.
if ($env:DEPTEX_RULE_GENERATION_ENABLED) { $EnvFlags += @('-e', "DEPTEX_RULE_GENERATION_ENABLED=$($env:DEPTEX_RULE_GENERATION_ENABLED)") }
if ($env:DEPTEX_RULE_PROVIDER) { $EnvFlags += @('-e', "DEPTEX_RULE_PROVIDER=$($env:DEPTEX_RULE_PROVIDER)") }
if ($env:DEPTEX_RULE_MODEL) { $EnvFlags += @('-e', "DEPTEX_RULE_MODEL=$($env:DEPTEX_RULE_MODEL)") }
if ($env:DEPTEX_RULE_BUDGET_USD) { $EnvFlags += @('-e', "DEPTEX_RULE_BUDGET_USD=$($env:DEPTEX_RULE_BUDGET_USD)") }
if ($env:DEPTEX_RULE_GENERATION_PLATFORM_RULES_DIR) { $EnvFlags += @('-e', "DEPTEX_RULE_GENERATION_PLATFORM_RULES_DIR=$($env:DEPTEX_RULE_GENERATION_PLATFORM_RULES_DIR)") }

# Reachability-focused fast scan + OSV fallback (parity with the bash wrapper).
if ($env:DEPTEX_SKIP_OPTIONAL_SCANS) { $EnvFlags += @('-e', "DEPTEX_SKIP_OPTIONAL_SCANS=$($env:DEPTEX_SKIP_OPTIONAL_SCANS)") }
if ($env:DEPTEX_OSV_FALLBACK) { $EnvFlags += @('-e', "DEPTEX_OSV_FALLBACK=$($env:DEPTEX_OSV_FALLBACK)") }

# Arc 2 dep-import-graph knobs (pipeline-steps/dep-import-graph.ts).
if ($env:DEPTEX_DEP_IMPORT_WALL_MS) { $EnvFlags += @('-e', "DEPTEX_DEP_IMPORT_WALL_MS=$($env:DEPTEX_DEP_IMPORT_WALL_MS)") }
if ($env:DEPTEX_DEP_IMPORT_MAX_DISTS) { $EnvFlags += @('-e', "DEPTEX_DEP_IMPORT_MAX_DISTS=$($env:DEPTEX_DEP_IMPORT_MAX_DISTS)") }
if ($env:DEPTEX_DEP_IMPORT_DISABLE) { $EnvFlags += @('-e', "DEPTEX_DEP_IMPORT_DISABLE=$($env:DEPTEX_DEP_IMPORT_DISABLE)") }

# OpenAI-compatible third-party hosts. DEPTEX_RULE_BASE_URL routes the
# openai-style rule-generation call; the matching host-specific API key
# is forwarded by name (no =value) so secrets stay off docker's argv.
if ($env:DEPTEX_RULE_BASE_URL) { $EnvFlags += @('-e', "DEPTEX_RULE_BASE_URL=$($env:DEPTEX_RULE_BASE_URL)") }
if ($env:DEEPINFRA_API_KEY) { $EnvFlags += @('-e', 'DEEPINFRA_API_KEY') }
if ($env:OPENROUTER_API_KEY) { $EnvFlags += @('-e', 'OPENROUTER_API_KEY') }
if ($env:DASHSCOPE_API_KEY) { $EnvFlags += @('-e', 'DASHSCOPE_API_KEY') }
if ($env:OPENAI_API_KEY) { $EnvFlags += @('-e', 'OPENAI_API_KEY') }
if ($env:GOOGLE_API_KEY) { $EnvFlags += @('-e', 'GOOGLE_API_KEY') }
if ($env:GOOGLE_AI_API_KEY) { $EnvFlags += @('-e', 'GOOGLE_AI_API_KEY') }

# GitHub token (PAT or App installation) for authenticated patch-fetch
# rate limits. GITHUB_TOKEN is canonical; GITHUB_PAT is the fallback name.
if ($env:GITHUB_TOKEN) { $EnvFlags += @('-e', 'GITHUB_TOKEN') }
if ($env:GITHUB_PAT) { $EnvFlags += @('-e', 'GITHUB_PAT') }

# git GIT_CONFIG_COUNT/_KEY_n/_VALUE_n passthrough so callers can inject
# e.g. safe.directory=* to bypass git's dubious-ownership refusal.
if ($env:GIT_CONFIG_COUNT) {
  $EnvFlags += @('-e', "GIT_CONFIG_COUNT=$($env:GIT_CONFIG_COUNT)")
  for ($gci = 0; $gci -lt [int]$env:GIT_CONFIG_COUNT; $gci++) {
    $gck = "GIT_CONFIG_KEY_$gci"
    $gcv = "GIT_CONFIG_VALUE_$gci"
    $EnvFlags += @('-e', "$gck=$([Environment]::GetEnvironmentVariable($gck))")
    $EnvFlags += @('-e', "$gcv=$([Environment]::GetEnvironmentVariable($gcv))")
  }
}

docker run --rm -i `
  @EnvFlags `
  -v "${AbsWs}:/workspace" `
  -v "${AbsOut}:/output" `
  $Image `
  node /app/dist/cli/index.js run /workspace --output=/output @Passthrough

exit $LASTEXITCODE
