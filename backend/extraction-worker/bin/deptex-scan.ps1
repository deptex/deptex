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

docker run --rm -i `
  -v "${AbsWs}:/workspace" `
  -v "${AbsOut}:/output" `
  $Image `
  node /app/dist/cli/index.js run /workspace --output=/output @Passthrough

exit $LASTEXITCODE
