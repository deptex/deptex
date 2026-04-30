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
# environment instead of an encrypted BYOK row. ANTHROPIC_API_KEY uses
# the `-e VAR` (no =value) form so the secret never lands on docker's
# argv (visible via process listings and audit logs).
$EnvFlags = @('-e', 'DEPTEX_LOCAL_CLI=1')
if ($env:ANTHROPIC_API_KEY) { $EnvFlags += @('-e', 'ANTHROPIC_API_KEY') }
if ($env:ANTHROPIC_MODEL) { $EnvFlags += @('-e', "ANTHROPIC_MODEL=$($env:ANTHROPIC_MODEL)") }
if ($env:EPD_MAX_RUN_COST_USD) { $EnvFlags += @('-e', "EPD_MAX_RUN_COST_USD=$($env:EPD_MAX_RUN_COST_USD)") }
if ($env:EPD_BUDGET_EXCEEDED_BEHAVIOR) { $EnvFlags += @('-e', "EPD_BUDGET_EXCEEDED_BEHAVIOR=$($env:EPD_BUDGET_EXCEEDED_BEHAVIOR)") }
if ($env:EPD_MAX_VULNS_PER_RUN) { $EnvFlags += @('-e', "EPD_MAX_VULNS_PER_RUN=$($env:EPD_MAX_VULNS_PER_RUN)") }

docker run --rm -i `
  @EnvFlags `
  -v "${AbsWs}:/workspace" `
  -v "${AbsOut}:/output" `
  $Image `
  node /app/dist/cli/index.js run /workspace --output=/output @Passthrough

exit $LASTEXITCODE
