$ErrorActionPreference = 'Stop'

try {
    $modulePath = Join-Path $PSScriptRoot "hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "ERROR while loading charm module: $_"
    exit 1
}

try {
    Run-RelationHooks
} catch {
    juju-log.exe "ERROR while running devstack-relation-changed hook: $_"
    exit 1
}
