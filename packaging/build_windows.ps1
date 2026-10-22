<#
.SYNOPSIS
    Build jsfind-mcp into Windows .exe files.

.DESCRIPTION
    Produces one onefile executable in dist\:

        jsfind-mcp.exe   MCP server (stdio)

    The project has no CLI; every capability is an MCP tool.

.PARAMETER SkipTests
    Skip the smoke test that runs after building.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\build_windows.ps1
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$SkipVenv
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Say([string]$Message) {
    Write-Host "==> $Message" -ForegroundColor Cyan
}

# 1. An isolated interpreter, so the build never picks up the user's global
#    packages and never breaks their environment.
$Venv = Join-Path $Root '.build-venv'
if (-not $SkipVenv) {
    Say "creating build virtual environment"
    if (-not (Test-Path $Venv)) {
        python -m venv $Venv
    }
    $Python = Join-Path $Venv 'Scripts\python.exe'
} else {
    $Python = 'python'
}

Say "upgrading build tooling"
& $Python -m pip install --quiet --upgrade pip setuptools wheel

Say "installing runtime + build dependencies"
& $Python -m pip install --quiet -e .
& $Python -m pip install --quiet pyinstaller

Say "verifying the source imports before freezing"
& $Python -c "import jsfind_mcp; print('jsfind_mcp', jsfind_mcp.__version__)"

Say "running tests"
if (-not $SkipTests) {
    & $Python tests\test_banners.py
    if ($LASTEXITCODE -ne 0) { throw "banner tests failed" }
}

Say "building executables"
& $Python -m PyInstaller --clean --noconfirm --distpath dist --workpath build packaging\jsfind_mcp.spec
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }

$Cli = Join-Path $Root 'dist\jsfind-mcp.exe'
foreach ($path in @($Cli)) {
    if (-not (Test-Path $path)) { throw "expected executable missing: $path" }
}

Say "smoke-testing the frozen server"
& $Cli --print-config | Out-Null
if ($LASTEXITCODE -ne 0) { throw "frozen server failed to start" }

Say "smoke-testing the frozen MCP server"
& $Cli --help
if ($LASTEXITCODE -ne 0) { throw "frozen MCP server failed to start" }

$SizeCli = [math]::Round((Get-Item $Cli).Length / 1MB, 1)

Say "done"
Write-Host ""
Write-Host "  dist\jsfind-mcp.exe  $SizeCli MB" -ForegroundColor Green
Write-Host ""
Write-Host "MCP client config:"
Write-Host @"
{
  "mcpServers": {
    "jsfind-mcp": {
      "command": "$Cli"
    }
  }
}
"@
