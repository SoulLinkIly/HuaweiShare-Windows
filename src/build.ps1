param(
    [switch]$Test,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'

function Find-Tool {
    param(
        [string]$Name,
        [string]$EnvOverride,
        [string[]]$SearchRoots,
        [string]$Hint
    )

    $override = [Environment]::GetEnvironmentVariable($EnvOverride)
    if ($override) {
        if (Test-Path $override) { return (Resolve-Path $override).Path }
        Write-Host "[warn] $EnvOverride points at a missing file: $override"
    }

    $onPath = Get-Command $Name -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }

    foreach ($root in $SearchRoots) {
        if (-not (Test-Path $root)) { continue }
        $hit = Get-ChildItem -Path $root -Filter $Name -Recurse -Depth 4 -File -ErrorAction SilentlyContinue |
               Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    Write-Host "[ERROR] $Name not found."
    Write-Host "        $Hint"
    return $null
}

$cargoRoots = @(
    (Join-Path $env:USERPROFILE '.cargo\bin'),
    (Join-Path $env:USERPROFILE '.rustup\toolchains'),
    'C:\Program Files\Rust stable MSVC',
    'C:\Rust',
    'D:\Rust',
    'E:\work\soft\rust'
)

$cargo = Find-Tool -Name 'cargo.exe' -EnvOverride 'HWSHARE_CARGO' -SearchRoots $cargoRoots -Hint @'
Install the Rust toolchain (https://rustup.rs), or point HWSHARE_CARGO at cargo.exe:
  $env:HWSHARE_CARGO = 'C:\Users\you\.cargo\bin\cargo.exe'
'@
if (-not $cargo) { exit 1 }

$cargoBin = Split-Path $cargo -Parent
$env:PATH = "$cargoBin;$env:PATH"

$toolchainDir  = Split-Path $cargoBin -Parent
$toolchainsDir = Split-Path $toolchainDir -Parent
$rustupRoot    = Split-Path $toolchainsDir -Parent

if (-not $env:CARGO_HOME) {
    $candidates = @()
    if ((Split-Path $rustupRoot -Leaf) -eq 'rustup') {
        $candidates += (Join-Path (Split-Path $rustupRoot -Parent) 'cargo')
    }
    $candidates += (Join-Path $env:USERPROFILE '.cargo')
    foreach ($c in $candidates) {
        if (Test-Path (Join-Path $c 'registry')) { $env:CARGO_HOME = $c; break }
    }
}
if (-not $env:RUSTUP_HOME) {
    if (Test-Path (Join-Path $rustupRoot 'toolchains')) { $env:RUSTUP_HOME = $rustupRoot }
}

$windresRoots = @(
    'C:\w64devkit\bin',
    'C:\msys64\mingw64\bin',
    'C:\msys64\ucrt64\bin',
    'C:\Program Files\mingw64\bin',
    'E:\work\soft\w64devkit\bin',
    'D:\soft\w64devkit\bin'
)
$windres = Find-Tool -Name 'windres.exe' -EnvOverride 'HWSHARE_WINDRES' -SearchRoots $windresRoots -Hint @'
windres is optional: without it the exe has no icon and no version resource.
Install w64devkit (or any mingw-w64 build) and set HWSHARE_WINDRES:
  $env:HWSHARE_WINDRES = 'C:\w64devkit\bin\windres.exe'
'@
if ($windres) {
    $env:PATH = "$(Split-Path $windres -Parent);$env:PATH"
    $env:HWSHARE_WINDRES = $windres
} else {
    Write-Host "[warn] building without windres - exe will have no icon / version info"
}

$targetDir = Join-Path $env:LOCALAPPDATA 'HWShareWin\build'
if ($env:HWSHARE_TARGET_DIR) { $targetDir = $env:HWSHARE_TARGET_DIR }
$env:CARGO_TARGET_DIR = $targetDir

Write-Host "[info] cargo     : $cargo"
Write-Host "[info] windres   : $(if ($windres) { $windres } else { '(missing)' })"
Write-Host "[info] target dir: $targetDir"

$cargoArgs = @()
if ($Offline) { $cargoArgs += '--offline' }

$code = 0
Push-Location $PSScriptRoot
try {
    if ($Test) {
        & $cargo test --lib @cargoArgs
        $code = $LASTEXITCODE
    } else {
        & $cargo build --release @cargoArgs --bin hwshare --bin hwshare-cli
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            $outExes = @(
                (Join-Path $targetDir 'release\hwshare.exe'),
                (Join-Path $targetDir 'release\hwshare-cli.exe')
            )
            Write-Host ""
            foreach ($exe in $outExes) { Write-Host "[OK] $exe" }

            $parentBin = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin'
            $localBin = Join-Path $PSScriptRoot 'bin'
            $binDir = if (Test-Path $parentBin) { $parentBin }
                      elseif (Test-Path $localBin) { $localBin }
                      else { $null }
            if ($binDir) {
                foreach ($exe in $outExes) {
                    Copy-Item $exe (Join-Path $binDir (Split-Path $exe -Leaf)) -Force
                    Write-Host "[OK] copied to $(Join-Path $binDir (Split-Path $exe -Leaf))"
                }
            }
        }
    }
} finally {
    Pop-Location
}
exit $code
