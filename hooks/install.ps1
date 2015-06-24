$ErrorActionPreference = 'Stop'

try {
    $modulePath = Join-Path $PSScriptRoot "hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "ERROR while loading charm module: $_"
    exit 1
}

try {
    Run-InstallHook
} catch {
    juju-log.exe "ERROR while running install hook: $_"
    exit 1
}
