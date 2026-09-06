[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Arguments
)

# Keep uninstall as a separate discoverable entry point while sharing the
# frozen parser and purge implementation with install.ps1.
$scriptPath = Join-Path $PSScriptRoot 'install.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $scriptPath uninstall @Arguments
exit $LASTEXITCODE
