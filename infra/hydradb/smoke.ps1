$ErrorActionPreference = "Stop"

# Find the repository root from this script's location.
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$tokenPath = Join-Path $repoRoot "hydradb-data\auth-token"
$readyUri = "http://127.0.0.1:9090/readyz"
$queryUri = "http://127.0.0.1:8443/v1/graphs/default/query"

# The local token must exist, but it must never be printed.
if (-not (Test-Path $tokenPath)) {
    throw "HydraDB token was not found at: $tokenPath"
}

$token = (Get-Content $tokenPath -Raw).Trim()

if ($token.Length -lt 32) {
    throw "HydraDB development token must contain at least 32 characters."
}

Write-Host "Checking HydraDB readiness..."

$readinessResponse = Invoke-WebRequest `
    -Uri $readyUri `
    -UseBasicParsing

if ($readinessResponse.StatusCode -ne 200) {
    throw "HydraDB readiness check failed with status $($readinessResponse.StatusCode)."
}

Write-Host "HydraDB is ready."

$headers = @{
    Authorization       = "Bearer $token"
    "X-Graph-Namespace" = "default"
}

# MERGE makes this test safe to run more than once.
$writeQuery = @"
MERGE (source:Smoke {
  id: 9900001,
  name: 'hydrascope-smoke-source'
})-[:SMOKE_LINK]->(target:Smoke {
  id: 9900002,
  name: 'hydrascope-smoke-target'
})
"@

$writeBody = @{
    cell_id = "cell-0"
    query   = $writeQuery
} | ConvertTo-Json -Compress

Write-Host "Writing two nodes and one relationship..."

Invoke-RestMethod `
    -Method Post `
    -Uri $queryUri `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $writeBody | Out-Null

$readQuery = @"
MATCH (source:Smoke {id: 9900001})-[:SMOKE_LINK]->(target:Smoke {id: 9900002})
RETURN target.id AS target_id
"@

$readBody = @{
    cell_id = "cell-0"
    query   = $readQuery
} | ConvertTo-Json -Compress

Write-Host "Reading the relationship back from HydraDB..."

$response = Invoke-RestMethod `
    -Method Post `
    -Uri $queryUri `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $readBody

if ($null -eq $response.rows -or $response.rows.Count -lt 1) {
    throw "HydraDB returned no rows for the smoke-test relationship."
}

$returnedTargetId = [Int64]$response.rows[0][0].value

if ($returnedTargetId -ne 9900002) {
    throw "Expected target ID 9900002, but HydraDB returned $returnedTargetId."
}

Write-Host ""
Write-Host "HydraDB write/read smoke test passed." -ForegroundColor Green
Write-Host "Source node: 9900001"
Write-Host "Relationship: SMOKE_LINK"
Write-Host "Target node: $returnedTargetId"
