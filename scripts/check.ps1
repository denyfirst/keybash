param([switch]$Analysis)
$ErrorActionPreference = 'Stop'
$taskRepoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $taskRepoRoot
try {
    $taskUnformatted = @(gofmt -l internal web)
    if ($LASTEXITCODE -ne 0 -or $taskUnformatted.Count -ne 0) { throw 'format check failed' }
    node --test web/paste.test.mjs
    if ($LASTEXITCODE -ne 0) { throw 'paste tests failed' }
    go mod verify
    if ($LASTEXITCODE -ne 0) { throw 'module verification failed' }
    $taskDependencies = @(go list -deps -test ./...)
    if ($LASTEXITCODE -ne 0) { throw 'dependency inventory failed' }
    if ($taskDependencies -match '^golang.org/x/crypto/openpgp($|/)') { throw 'unmaintained OpenPGP dependency is forbidden' }
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'vet failed' }
    go test -shuffle=on -count=1 ./...
    if ($LASTEXITCODE -ne 0) { throw 'tests failed' }
    go build -trimpath ./...
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
    if ($Analysis) {
        staticcheck ./...
        if ($LASTEXITCODE -ne 0) { throw 'staticcheck failed' }
        gosec -severity medium -confidence medium ./...
        if ($LASTEXITCODE -ne 0) { throw 'gosec failed' }
        govulncheck ./...
        if ($LASTEXITCODE -ne 0) { throw 'govulncheck failed' }
        actionlint
        if ($LASTEXITCODE -ne 0) { throw 'actionlint failed' }
    }
}
finally { Pop-Location }
