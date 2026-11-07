# Build / test helper.
#
#   .\build.ps1                 release build (hwshare.exe + hwshare-cli.exe)
#   .\build.ps1 -Test           unit tests
#   .\build.ps1 -Offline        pass --offline to cargo (needs a warm registry cache)
#   .\build.ps1 -Test -Offline  both
#
# ASCII only on purpose: PowerShell 5.1 reads .ps1 as ANSI, non-ASCII bytes
# inside string literals get mangled.
#
# Toolchain discovery
# -------------------
# Nothing is hard-wired to one machine. Each tool is looked up in this order:
#   1. explicit env override      $env:HWSHARE_CARGO / $env:HWSHARE_WINDRES
#   2. PATH
#   3. a list of well-known install roots (rustup default, the layout used on
#      the machine this project came from, common mingw locations)
# Missing cargo is fatal with an install hint. Missing windres is only a warning:
# the exe still builds, it just has no icon / version resource.

param(
    [switch]$Test,
    [switch]$Offline
)

$ErrorActionPreference = 'Stop'

function Find-Tool {
    param(
        [string]$Name,                  # exe file name, e.g. cargo.exe
        [string]$EnvOverride,           # env var that may point at it
        [string[]]$SearchRoots,         # directories to search (recursive, depth 4)
        [string]$Hint                   # printed when nothing is found
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

# ---------------------------------------------------------------- cargo / rustc
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

# cargo shells out to rustc and the linker; they live next to it on a rustup install.
$cargoBin = Split-Path $cargo -Parent
$env:PATH = "$cargoBin;$env:PATH"

# Fill CARGO_HOME / RUSTUP_HOME in only when the user has not set them.
# The registry cache lives under CARGO_HOME, so guessing this wrong makes
# `-Offline` fail with "no matching package found" even though the cache exists.
$toolchainDir  = Split-Path $cargoBin -Parent          # ...\toolchains\<triple>
$toolchainsDir = Split-Path $toolchainDir -Parent      # ...\toolchains
$rustupRoot    = Split-Path $toolchainsDir -Parent     # ...\rustup

if (-not $env:CARGO_HOME) {
    $candidates = @()
    # rustup layout puts CARGO_HOME next to RUSTUP_HOME: <root>\rustup + <root>\cargo
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

# ---------------------------------------------------------------- windres
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

# ---------------------------------------------------------------- target dir
# mingw ld cannot open intermediate .o files when the path contains non-ASCII
# characters (Chinese folder names) and reports "No such file or directory" for
# every object. Keep the target dir ASCII and outside the project by default.
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
# cargo writes its progress to stderr; with ErrorActionPreference=Stop PowerShell
# turns that into NativeCommandError and aborts a perfectly good build.
# Keep Stop for tool discovery, relax it only for the native calls below.
$ErrorActionPreference = 'Continue'
try {
    if ($Test) {
        & $cargo test @cargoArgs 2>&1 | ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
    } else {
        # Two products from one shared implementation:
        #   hwshare.exe      GUI subsystem, tray/drop window, no console
        #   hwshare-cli.exe  console subsystem, CLI subcommands only
        & $cargo build --release @cargoArgs --bin hwshare --bin hwshare-cli 2>&1 |
            ForEach-Object { Write-Host $_ }
        $code = $LASTEXITCODE
        if ($code -eq 0) {
            $outExes = @(
                (Join-Path $targetDir 'release\hwshare.exe'),
                (Join-Path $targetDir 'release\hwshare-cli.exe')
            )
            Write-Host ""
            foreach ($exe in $outExes) { Write-Host "[OK] $exe" }

            # Copy next to the project so double-click / distribution uses this build.
            # Two layouts are supported:
            #   <root>\bin + <root>\src\build.ps1   (release tree)
            #   <root>\bin + <root>\build.ps1       (flat dev tree)
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
