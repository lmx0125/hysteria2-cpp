# setup_openssl.ps1 — Downloads pre-built OpenSSL 3.5.0 for Windows
# Run from the hy2-cpp directory: powershell -ExecutionPolicy Bypass -File third_party/setup_openssl.ps1

$ErrorActionPreference = "Stop"

$OPENSSL_VERSION = "3.5.0"
$OPENSSL_DIR = Join-Path $PSScriptRoot "..\build\_deps\openssl"

# Use slproweb.com pre-built binaries (the standard Windows OpenSSL distribution)
$ARCH = if ([Environment]::Is64BitOperatingSystem) { "Win64" } else { "Win32" }
$URL = "https://slproweb.com/download/Win64OpenSSL-$($OPENSSL_VERSION.Replace('.','')).exe"

Write-Host "OpenSSL $OPENSSL_VERSION ($ARCH)" -ForegroundColor Cyan
Write-Host "Download URL: $URL"

if (Test-Path "$OPENSSL_DIR\include\openssl\ssl.h") {
    Write-Host "OpenSSL already present at $OPENSSL_DIR — skipping download." -ForegroundColor Green
    exit 0
}

New-Item -ItemType Directory -Path $OPENSSL_DIR -Force | Out-Null

Write-Host "Downloading OpenSSL installer..."
$installer = Join-Path $env:TEMP "openssl_installer.exe"
Invoke-WebRequest -Uri $URL -OutFile $installer -UseBasicParsing

Write-Host "Installing OpenSSL to $OPENSSL_DIR ..."
Start-Process -FilePath $installer -ArgumentList "/SILENT /NORESTART /DIR=$OPENSSL_DIR /NO桌面快捷方式" -Wait

if (Test-Path "$OPENSSL_DIR\include\openssl\ssl.h") {
    Write-Host "OpenSSL installed successfully at $OPENSSL_DIR" -ForegroundColor Green
} else {
    Write-Host "Installation may have failed. Check $OPENSSL_DIR" -ForegroundColor Yellow
    Write-Host "Alternative: install manually from https://slproweb.com/products/Win32OpenSSL.html"
    Write-Host "  or use vcpkg: vcpkg install openssl:x64-windows"
    exit 1
}
