
# Build Vcpkg and install dependency packages.
#
# Usage: .ci\install-vcpkg.ps1 <project directory> [vcpkg directory name]
# - project directory: Path to the project sources where the .vcpkg file is located.
# - vcpkg directory name: optional name of directory where Vcpkg will be clone'd into
#
# Example 1: .ci\install-vcpkg.ps1 $Env:GITHUB_WORKSPACE
# Example 2: .ci\install-vcpkg.ps1 $Env:APPVEYOR_BUILD_FOLDER vcpkg-msvc

$ErrorActionPreference="Stop"

if ($args.Count -lt 1) { Exit 1 }

$PROJECT_DIR=$args[0]
$VCPKG_DIR=$args[1]

if ($null -eq $VCPKG_DIR) { $VCPKG_DIR="vcpkg" }

# do nothing if .vcpkg file doesn't exist
if (-not (Test-Path "$PROJECT_DIR\.vcpkg" -PathType Leaf)) { Write-Host ".vcpkg file does not exist, skipping Vcpkg installation."; Exit 0 }

Write-Host "---- install-vcpkg.ps1 ----"
Write-Host "PROJECT_DIR: $PROJECT_DIR"
Write-Host "VCPKG_DIR: $VCPKG_DIR"
Write-Host "---------------------------"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    New-Alias -Name git -Value "$Env:ProgramFiles\Git\bin\git.exe"
}

Push-Location "$HOME"
git clone --quiet --depth 1 https://github.com/Microsoft/vcpkg.git $VCPKG_DIR
Set-Location $VCPKG_DIR
.\bootstrap-vcpkg.bat -disableMetrics
$packages = Get-Content "$PROJECT_DIR\.vcpkg"
.\vcpkg.exe install --triplet x64-windows $packages
Pop-Location