param([switch]$Check)
$ErrorActionPreference = 'Stop'
$taskDemoRoot = Split-Path -Parent $PSScriptRoot
$taskDemoPreviousOptIn = $env:KEYBASH_INTERACTIVE_DEMO
$taskDemoPreviousChannel = $env:KEYBASH_BROWSER_CHANNEL
Push-Location $taskDemoRoot
try {
    # Use existing development runtimes. Never install a browser, alter system
    # TLS trust, read real credentials or change another product's checkout.
    $null = Get-Command go -ErrorAction Stop
    $null = Get-Command node -ErrorAction Stop
    if (-not (Test-Path -LiteralPath (Join-Path $taskDemoRoot 'web/node_modules/playwright'))) {
        throw 'Pinned web development dependencies are missing. See docs/INTERACTIVE-DEMO-AZ.md.'
    }
    if (-not $env:KEYBASH_BROWSER_CHANNEL -and [System.Environment]::OSVersion.Platform -eq 'Win32NT') { $env:KEYBASH_BROWSER_CHANNEL = 'msedge' }
    if ($Check) {
        go test -tags=browserlab -run='^TestDemoInputBoundary$|^TestDemoWorkerCancellation$|^TestInteractiveDemoBrowser$' -count=1 -timeout=2m ./internal/identity
    } else {
        $env:KEYBASH_INTERACTIVE_DEMO = '1'
        go test -tags=browserlab -run='^TestInteractiveDemo$' -count=1 -timeout=65m -v ./internal/identity
    }
    if ($LASTEXITCODE -ne 0) { throw 'Keybash demo failed. No production service was started.' }
}
finally {
    $env:KEYBASH_INTERACTIVE_DEMO = $taskDemoPreviousOptIn
    $env:KEYBASH_BROWSER_CHANNEL = $taskDemoPreviousChannel
    Pop-Location
}
