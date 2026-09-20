#requires -Version 7.0

<#
    .SYNOPSIS
        Asks Entra what its Conditional Access policies would actually do, and
        fails when that disagrees with the scenario matrix.
    .DESCRIPTION
        The policies deploy report-only, so nothing is enforced while this runs.
        The evaluation is asked the predictive question -- what would happen if
        these were enforced -- because a lockout is only cheap to fix before
        promotion.

        Two independent checks have to pass. The matrix comparison says the
        policies do what was intended. The lockout analysis says the break-glass
        accounts can still get in. The second is not implied by the first: a
        matrix can be entirely satisfied by policies that also happen to shut
        out every account capable of rolling them back.
    .PARAMETER TenantId
        The lab directory. Never a directory holding production mail.
    .PARAMETER MatrixPath
        The scenario matrix.
    .PARAMETER IdentityMap
        Symbolic identity name to object ID, from the Terraform outputs.
    .PARAMETER BreakGlassId
        Object IDs of the accounts that must never lose access.
    .PARAMETER ReportPath
        Where to write the JSON report.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TenantId,
    [Parameter(Mandatory)][string]$MatrixPath,
    [Parameter(Mandatory)][hashtable]$IdentityMap,
    [Parameter(Mandatory)][string[]]$BreakGlassId,
    [string]$ReportPath = 'cutover-proof.json'
)

$ErrorActionPreference = 'Stop'
# Write-Information rather than Write-Host, so the progress narration travels on
# a stream a caller can redirect or silence.
$InformationPreference = 'Continue'
Set-StrictMode -Version Latest

Import-Module ([System.IO.Path]::Combine($PSScriptRoot, '..', 'module', 'HybridIdentity', 'HybridIdentity.psm1')) -Force -ErrorAction Stop

function Get-GraphToken {
    $raw = az account get-access-token --resource 'https://graph.microsoft.com' --tenant $TenantId -o json
    if ($LASTEXITCODE -ne 0) { throw "Could not obtain a Microsoft Graph token for tenant $TenantId." }
    $token = ($raw | ConvertFrom-Json).accessToken
    if ([string]::IsNullOrWhiteSpace($token)) { throw 'The token response carried no access token.' }
    return $token
}

function Invoke-Graph {
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [object]$Body,
        [Parameter(Mandatory)][string]$Token
    )

    $headers = @{ Authorization = "Bearer $Token"; 'Content-Type' = 'application/json' }
    $arguments = @{ Method = $Method; Uri = $Uri; Headers = $headers; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body')) {
        $arguments['Body'] = ($Body | ConvertTo-Json -Depth 12 -Compress)
    }

    try {
        return Invoke-RestMethod @arguments
    }
    catch {
        $detail = $_.ErrorDetails.Message
        if ([string]::IsNullOrWhiteSpace($detail)) { $detail = $_.Exception.Message }
        throw "Graph $Method $Uri failed: $detail"
    }
}

# ReadAllText, not Get-Content -Raw. Get-Content decorates its output with ETS
# properties whose object graphs make a deep ConvertTo-Json walk forever.
$matrix = [System.IO.File]::ReadAllText($MatrixPath) | ConvertFrom-Json
$token = Get-GraphToken

Write-Information "Evaluating $(@($matrix.scenarios).Count) scenarios against tenant $TenantId."

$evaluation = @{}
foreach ($scenario in $matrix.scenarios) {
    $userId = $IdentityMap[$scenario.identity]
    if ([string]::IsNullOrWhiteSpace($userId)) {
        throw "Scenario '$($scenario.name)' names identity '$($scenario.identity)', which is not in the identity map."
    }

    $appId = $matrix.applications.($scenario.application)
    if ([string]::IsNullOrWhiteSpace($appId)) {
        throw "Scenario '$($scenario.name)' names application '$($scenario.application)', which the matrix does not define."
    }

    $conditions = @{}
    foreach ($property in $scenario.conditions.PSObject.Properties) {
        $conditions[$property.Name] = $property.Value
    }

    $body = @{
        signInIdentity = @{
            '@odata.type' = '#microsoft.graph.userSignIn'
            userId        = $userId
        }
        signInContext  = @{
            '@odata.type'       = '#microsoft.graph.applicationContext'
            includeApplications = @($appId)
        }
        signInConditions = $conditions
        # False on purpose. Asking only for applied policies throws away the
        # analysisReasons on the ones that did not apply, and those reasons are
        # how an evaluation that could not be made is told apart from one that
        # came back negative.
        appliedPoliciesOnly = $false
    }

    $response = Invoke-Graph -Method POST -Token $token `
        -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/evaluate' -Body $body

    $evaluation[$scenario.name] = @($response.value)
    Write-Information "  evaluated: $($scenario.name)"
}

$comparison = @(Compare-EvaluationToMatrix -Scenario $matrix.scenarios -Evaluation $evaluation -TreatReportOnlyAsEnforced)

# The second check. The policies are read back from the directory rather than
# from the Terraform plan, so drift applied by hand in the portal is caught too.
$policies = @((Invoke-Graph -Method GET -Token $token `
    -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies').value)

$accounts = foreach ($id in $BreakGlassId) {
    $user = Invoke-Graph -Method GET -Token $token -Uri "https://graph.microsoft.com/v1.0/users/$id`?`$select=id,displayName"
    $memberOf = @((Invoke-Graph -Method GET -Token $token -Uri "https://graph.microsoft.com/v1.0/users/$id/memberOf`?`$select=id").value)
    $methods = @((Invoke-Graph -Method GET -Token $token -Uri "https://graph.microsoft.com/v1.0/users/$id/authentication/methods").value)

    # A password is not a second factor. Anything else registered is.
    $strong = @($methods | Where-Object { $_.'@odata.type' -ne '#microsoft.graph.passwordAuthenticationMethod' })

    [pscustomobject]@{
        id                     = $user.id
        displayName            = $user.displayName
        groupIds               = @($memberOf | ForEach-Object { $_.id })
        roleIds                = @()
        hasMfaMethod           = ($strong.Count -gt 0)
        usesCompliantDevice    = $false
        usesDomainJoinedDevice = $false
        usesApprovedClientApp  = $false
    }
}

$lockout = @(Test-LockoutRisk -Policy $policies -BreakGlassAccount @($accounts))

$mismatches = @($comparison | Where-Object { -not $_.Match })
$critical = @($lockout | Where-Object { $_.Severity -in @('Critical', 'High') })

$report = [pscustomobject]@{
    tenantId    = $TenantId
    evaluatedAt = (Get-Date).ToUniversalTime().ToString('o')
    scenarios   = $comparison
    lockout     = $lockout
    summary     = [pscustomobject]@{
        scenarioCount = $comparison.Count
        mismatchCount = $mismatches.Count
        lockoutCount  = $critical.Count
        policyCount   = $policies.Count
    }
}

[System.IO.File]::WriteAllText($ReportPath, ($report | ConvertTo-Json -Depth 10),
    (New-Object System.Text.UTF8Encoding($false)))

Write-Information ''
Write-Information '--- scenario matrix ---'
foreach ($row in $comparison) {
    $mark = if ($row.Match) { 'ok  ' } else { 'FAIL' }
    Write-Information ("  {0} {1,-48} {2}" -f $mark, $row.Scenario, $row.Detail)
}

Write-Information ''
Write-Information '--- break-glass ---'
if ($lockout.Count -eq 0) {
    Write-Information '  ok   every break-glass account can still reach a recovery surface.'
}
else {
    foreach ($row in $lockout) { Write-Information ("  {0,-8} {1}" -f $row.Severity, $row.Detail) }
}

if ($env:GITHUB_STEP_SUMMARY) {
    $lines = @(
        '### Cutover proof'
        ''
        "| | |"
        "|---|---|"
        "| Scenarios evaluated | $($comparison.Count) |"
        "| Disagreements with the matrix | $($mismatches.Count) |"
        "| Break-glass lockouts | $($critical.Count) |"
        "| Policies read back from the directory | $($policies.Count) |"
        ''
        '| Scenario | Expected | Entra says | |'
        '|---|---|---|---|'
    )
    foreach ($row in $comparison) {
        $mark = if ($row.Match) { 'ok' } else { '**fail**' }
        $lines += "| $($row.Scenario) | $($row.Expected) | $($row.Actual) | $mark |"
    }
    $lines | Out-File $env:GITHUB_STEP_SUMMARY -Append
}

if ($mismatches.Count -or $critical.Count) {
    throw "Proof failed: $($mismatches.Count) scenario(s) disagree with the matrix and $($critical.Count) break-glass lockout(s) were found. These policies must not be promoted to enforced."
}

Write-Information ''
Write-Information "All $($comparison.Count) scenarios match and no break-glass account is locked out. These policies are safe to enforce."
