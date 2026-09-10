# build-windows.ps1 — build the three Go tools + bundle the EFI and BYOVD
# runtime into a single ZIP. Run locally with PowerShell 7+ on Windows
# or Linux (pwsh + Go 1.23+); the GitHub Actions release workflow does
# the same on windows-2022.
#
# Usage:
#   pwsh tools/build-windows.ps1 -Source . -Out cmp50hx-unlock-windows.zip
#   pwsh tools/build-windows.ps1 -Source . -Out .\build\cmp50hx.zip -Version v0.1.30
#   pwsh tools/build-windows.ps1 -Source . -Out x.zip -SkipGo    # skip Go build (debug)

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]  [string]$Source,
    [Parameter(Mandatory = $true)]  [string]$Out,
    [string]$Version = (git -C $Source describe --tags --always --dirty 2>$null; if (-not $?) { 'dev' } else { $LASTEXITCODE = 0; 'dev' }),
    [switch]$SkipGo = $false
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Req([string]$name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        throw "missing required tool: $name"
    }
}

Req pwsh
if (-not $SkipGo) { Req go }

$Source = (Resolve-Path $Source).Path
$OutAbs = [System.IO.Path]::GetFullPath((Join-Path (Get-Location) $Out))
$Stage = Join-Path ([System.IO.Path]::GetTempPath()) ("cmp50hx-win-stage-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

try {
    if (-not $SkipGo) {
        # 1. winres_gen (one-shot, generates rsrc_windows_amd64.syso)
        $winresSrc = Join-Path $Source 'tools/winres_gen'
        $winresOut = Join-Path $Stage 'winres_gen.exe'
        Write-Host ">> building winres_gen" -ForegroundColor Cyan
        Push-Location $winresSrc
        try { go build -o $winresOut . } finally { Pop-Location }
        if (-not (Test-Path (Join-Path $Source 'tools/inst50hx/rsrc_windows_amd64.syso'))) {
            Write-Host ">> generating rsrc_windows_amd64.syso" -ForegroundColor Cyan
            & $winresOut -o (Join-Path $Source 'tools/inst50hx/rsrc_windows_amd64.syso')
        }

        # 2. three Go tools (-H=windowsgui so no console window)
        $ldflags = '-H=windowsgui -s -w'
        $tools = @(
            @{ Name = '50HXInstaller.exe';   Dir = 'tools/inst50hx' },
            @{ Name = '50HXUninstaller.exe'; Dir = 'tools/uninstall50x' },
            @{ Name = '50HXCheck.exe';       Dir = 'tools/check50x' },
        )
        foreach ($t in $tools) {
            Write-Host ">> building $($t.Name)" -ForegroundColor Cyan
            Push-Location (Join-Path $Source $t.Dir)
            try { go build -a -trimpath -ldflags=$ldflags -o (Join-Path $Stage $t.Name) . }
            finally { Pop-Location }
        }
    } else {
        # When skipping the Go build, expect pre-built tools at expected paths.
        foreach ($name in '50HXInstaller.exe','50HXUninstaller.exe','50HXCheck.exe') {
            $candidates = @(
                (Join-Path $Source "artifacts/windows-stage/$name"),
                (Join-Path $Source "tools/inst50hx/$name"),
                (Join-Path $Source "tools/uninstall50x/$name"),
                (Join-Path $Source "tools/check50x/$name")
            )
            $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
            if (-not $found) { throw "SkipGo: $name not found in any expected path" }
            Copy-Item -Force $found (Join-Path $Stage $name)
        }
    }

    # 3. bundle: copy Gen2 BYOVD runtime + EFI + docs
    Write-Host ">> bundling runtime + EFI + docs" -ForegroundColor Cyan
    $gen2Src = Join-Path $Source 'gen2'
    if (Test-Path $gen2Src) {
        Copy-Item -Recurse -Force (Join-Path $gen2Src '*') $Stage
    } else {
        throw "missing gen2/ (BYOVD runtime)"
    }
    $efiSrc = Join-Path $Source 'efi-unlock/50HXUNLK.EFI'
    if (-not (Test-Path $efiSrc)) {
        Write-Host ">> warning: efi-unlock/50HXUNLK.EFI missing - run make efi first" -ForegroundColor Yellow
    } else {
        Copy-Item -Force $efiSrc (Join-Path $Stage '50HXUNLK.EFI')
        $hash = (Get-FileHash $efiSrc -Algorithm SHA256).Hash
        Write-Host "   embedded EFI sha256: $hash"
        "$hash  50HXUNLK.EFI" | Set-Content -NoNewline (Join-Path $Stage '50HXUNLK.EFI.sha256')
    }
    if (Test-Path (Join-Path $Source 'efi-unlock-windows/README.md')) {
        Copy-Item -Force (Join-Path $Source 'efi-unlock-windows/README.md') (Join-Path $Stage 'README.md')
    }
    foreach ($name in 'LICENSE') {
        foreach ($dir in @('CMP40HX-Unlock','.')) {
            $p = Join-Path $Source "$dir/$name"
            if (Test-Path $p) {
                Copy-Item -Force $p (Join-Path $Stage "LICENSE-$dir")
                break
            }
        }
    }

    # 4. ZIP it
    Write-Host ">> creating $OutAbs" -ForegroundColor Cyan
    $OutDir = Split-Path -Parent $OutAbs
    if ($OutDir -and -not (Test-Path $OutDir)) {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    }
    if (Test-Path $OutAbs) { Remove-Item $OutAbs }
    Compress-Archive -Path (Join-Path $Stage '*') -DestinationPath $OutAbs -CompressionLevel Optimal
    $sha = (Get-FileHash $OutAbs -Algorithm SHA256).Hash
    "$sha  $(Split-Path -Leaf $OutAbs)" | Set-Content -NoNewline "$OutAbs.sha256"
    Write-Host "wrote $OutAbs ($((Get-Item $OutAbs).Length) bytes) sha256=$sha" -ForegroundColor Green
}
finally {
    if (Test-Path $Stage) { Remove-RecurseSafe $Stage }
}

function Remove-RecurseSafe([string]$p) {
    if (Test-Path $p) { Remove-Item -Recurse -Force $p }
}
