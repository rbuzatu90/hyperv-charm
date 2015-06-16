$ErrorActionPreference = 'Stop'

try {
    $modulePath = Join-Path $PSScriptRoot "hooks.psm1"
    Import-Module -Force -DisableNameChecking $modulePath
} catch {
    juju-log.exe "ERROR while loading charm module: $_"
    exit 1
}

try {
    Run-ADRelationJoinedHook
} catch {
    juju-log.exe "ERROR while running ad-join-relation-joined hook: $_"
    exit 1
}
