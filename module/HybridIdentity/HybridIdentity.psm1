#requires -Version 7.0

Set-StrictMode -Version Latest

# The application IDs a locked-out administrator needs in order to get back in.
# A Conditional Access policy that blocks a single line-of-business app is not a
# lockout, however alarming it reads; a policy that blocks these is. Checking
# this is the difference between a report an operator acts on and one they learn
# to scroll past.
$script:RecoverySurfaces = @{
    '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
    'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure portal'
    '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Admin Portals'
    '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph PowerShell'
}

# Directory roles that can undo a bad Conditional Access policy. Anything else
# is privileged in some sense, but holding it does not get you out of a lockout.
$script:RecoveryRoles = @{
    '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
    'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
    '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
}

function ConvertTo-Set {
    <#
        .SYNOPSIS
            Normalises a possibly-null, possibly-scalar Graph collection into a
            case-insensitive lookup.
        .DESCRIPTION
            Graph omits empty collections rather than returning [], and returns a
            bare string where a caller hand-builds a fixture. Object IDs come back
            in inconsistent case across endpoints, so every comparison in this
            module goes through here rather than using -contains on a raw array.
    #>
    [OutputType([System.Collections.Generic.HashSet[string]])]
    param([object]$Value)

    $set = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    # Comma operator, not a bare return. PowerShell unrolls an enumerable on the
    # way out of a function, so "return $set" emits the set's members: nothing at
    # all when it is empty, and a bare string when it holds one item.
    if ($null -eq $Value) { return ,$set }
    foreach ($item in @($Value)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            [void]$set.Add(([string]$item).Trim())
        }
    }
    return ,$set
}

function Get-OptionalProperty {
    <#
        .SYNOPSIS
            Reads a property that may be absent, without tripping StrictMode.
    #>
    param(
        [Parameter(Mandatory)][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Name
    )

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-PolicyScope {
    <#
        .SYNOPSIS
            Decides whether a Conditional Access policy applies to an account.
        .DESCRIPTION
            Conditional Access resolves scope by union of the include sets, minus
            the union of the exclude sets. Exclusion always wins, and it can be
            granted by group or by directory role rather than by object ID. A
            checker that compares only excludeUsers reports a break-glass account
            as unprotected when it is excluded via its break-glass group, which is
            how most tenants actually configure it.
        .OUTPUTS
            A record stating whether the policy is in scope and why.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][object]$Policy,
        [Parameter(Mandatory)][object]$Account
    )

    $users = Get-OptionalProperty (Get-OptionalProperty $Policy 'conditions') 'users'

    $accountId = [string](Get-OptionalProperty $Account 'id')
    $groups    = ConvertTo-Set (Get-OptionalProperty $Account 'groupIds')
    $roles     = ConvertTo-Set (Get-OptionalProperty $Account 'roleIds')

    $includeUsers  = ConvertTo-Set (Get-OptionalProperty $users 'includeUsers')
    $includeGroups = ConvertTo-Set (Get-OptionalProperty $users 'includeGroups')
    $includeRoles  = ConvertTo-Set (Get-OptionalProperty $users 'includeRoles')
    $excludeUsers  = ConvertTo-Set (Get-OptionalProperty $users 'excludeUsers')
    $excludeGroups = ConvertTo-Set (Get-OptionalProperty $users 'excludeGroups')
    $excludeRoles  = ConvertTo-Set (Get-OptionalProperty $users 'excludeRoles')

    $includedBy = $null
    if ($includeUsers.Contains('All'))            { $includedBy = 'every user in the tenant' }
    elseif ($includeUsers.Contains($accountId))   { $includedBy = 'named directly in includeUsers' }
    else {
        $viaGroup = @($groups | Where-Object { $includeGroups.Contains($_) })
        $viaRole  = @($roles  | Where-Object { $includeRoles.Contains($_) })
        if ($viaGroup.Count) { $includedBy = "member of included group $($viaGroup[0])" }
        elseif ($viaRole.Count) { $includedBy = "holder of included role $($viaRole[0])" }
    }

    $excludedBy = $null
    if ($excludeUsers.Contains($accountId)) { $excludedBy = 'named directly in excludeUsers' }
    else {
        $viaGroup = @($groups | Where-Object { $excludeGroups.Contains($_) })
        $viaRole  = @($roles  | Where-Object { $excludeRoles.Contains($_) })
        if ($viaGroup.Count) { $excludedBy = "member of excluded group $($viaGroup[0])" }
        elseif ($viaRole.Count) { $excludedBy = "holder of excluded role $($viaRole[0])" }
    }

    [pscustomobject]@{
        InScope    = [bool]($includedBy -and -not $excludedBy)
        IncludedBy = $includedBy
        ExcludedBy = $excludedBy
    }
}

function Test-PolicyTargetsRecovery {
    <#
        .SYNOPSIS
            Decides whether a policy covers a surface needed to undo it.
        .DESCRIPTION
            Returns the recovery surfaces the policy would apply to. A policy
            scoped to one SaaS application cannot lock an administrator out of the
            directory, so it is not a lockout risk no matter how blunt its grant
            controls are.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][object]$Policy)

    $apps = Get-OptionalProperty (Get-OptionalProperty $Policy 'conditions') 'applications'
    $include = ConvertTo-Set (Get-OptionalProperty $apps 'includeApplications')
    $exclude = ConvertTo-Set (Get-OptionalProperty $apps 'excludeApplications')

    if ($include.Contains('All')) {
        $covered = @($script:RecoverySurfaces.Keys | Where-Object { -not $exclude.Contains($_) })
        return [string[]]@($covered | ForEach-Object { $script:RecoverySurfaces[$_] } | Sort-Object)
    }

    $named = @($include | Where-Object {
        $script:RecoverySurfaces.ContainsKey($_) -and -not $exclude.Contains($_)
    })
    return [string[]]@($named | ForEach-Object { $script:RecoverySurfaces[$_] } | Sort-Object)
}

function Test-GrantSatisfiable {
    <#
        .SYNOPSIS
            Decides whether an account could satisfy a policy's grant controls.
        .DESCRIPTION
            Grant controls combine under an operator: OR means any one control
            gets you in, AND means all of them must be met. A break-glass account
            deliberately has no registered MFA method and sits on no managed
            device, so "require MFA" and "require compliant device" are both
            absolute barriers to it even though neither says the word block.
        .OUTPUTS
            A record with Satisfiable, the control that would let the account
            through, and any requirement that could not be judged from the facts
            given.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$GrantControls,
        [Parameter(Mandatory)][object]$Account
    )

    # A policy with no grant controls sets session behaviour only. It cannot
    # refuse a sign-in, so it cannot lock anyone out.
    if ($null -eq $GrantControls) {
        return [pscustomobject]@{ Satisfiable = $true; SatisfiedBy = 'no grant controls'; Unevaluated = $null }
    }

    $controls = ConvertTo-Set (Get-OptionalProperty $GrantControls 'builtInControls')
    $strength = Get-OptionalProperty $GrantControls 'authenticationStrength'
    $operator = [string](Get-OptionalProperty $GrantControls 'operator')
    if ([string]::IsNullOrWhiteSpace($operator)) { $operator = 'OR' }

    # Block is not one requirement among several. Where it appears the answer is
    # no, whatever the operator claims.
    if ($controls.Contains('block')) {
        return [pscustomobject]@{ Satisfiable = $false; SatisfiedBy = $null; Unevaluated = $null }
    }

    $can = @{
        'mfa'                  = [bool](Get-OptionalProperty $Account 'hasMfaMethod')
        'compliantDevice'      = [bool](Get-OptionalProperty $Account 'usesCompliantDevice')
        'domainJoinedDevice'   = [bool](Get-OptionalProperty $Account 'usesDomainJoinedDevice')
        'approvedApplication'  = [bool](Get-OptionalProperty $Account 'usesApprovedClientApp')
        'compliantApplication' = [bool](Get-OptionalProperty $Account 'usesApprovedClientApp')
        'passwordChange'       = $true
    }

    $unevaluated = $null
    $results = [ordered]@{}
    foreach ($control in $controls) {
        if ($can.ContainsKey($control)) {
            $results[$control] = $can[$control]
        }
        else {
            # An unrecognised control must not be assumed satisfiable. Guessing
            # here is how a check comes back clean about something it never read.
            $results[$control] = $false
            $unevaluated = "grant control '$control' is not recognised and was treated as unsatisfiable"
        }
    }

    if ($null -ne $strength) {
        $name = [string](Get-OptionalProperty $strength 'displayName')
        if ([string]::IsNullOrWhiteSpace($name)) { $name = 'an authentication strength' }
        $satisfied = Get-OptionalProperty $Account 'satisfiesAuthenticationStrength'
        if ($null -eq $satisfied) {
            $results["strength:$name"] = $false
            $unevaluated = "the account's facts do not say whether it satisfies '$name', so it was treated as unsatisfiable"
        }
        else {
            $results["strength:$name"] = [bool]$satisfied
        }
    }

    if ($results.Count -eq 0) {
        return [pscustomobject]@{ Satisfiable = $true; SatisfiedBy = 'no grant controls'; Unevaluated = $unevaluated }
    }

    $met = @($results.Keys | Where-Object { $results[$_] })
    $satisfiable = if ($operator -eq 'AND') { $met.Count -eq $results.Count } else { $met.Count -gt 0 }

    [pscustomobject]@{
        Satisfiable = $satisfiable
        SatisfiedBy = if ($satisfiable -and $met.Count) { $met[0] } else { $null }
        Unevaluated = $unevaluated
    }
}

function Test-LockoutRisk {
    <#
        .SYNOPSIS
            Reports the Conditional Access policies that would shut a
            break-glass account out of the directory.
        .DESCRIPTION
            Every element has to hold at once for a policy to be a lockout: it
            must be on, it must apply to the account after exclusions, it must
            cover a surface the account needs to undo it, and the account must be
            unable to satisfy its grant controls. Dropping any one of those four
            tests produces a report full of policies that are fine, which is the
            same as no report at all.

            Report-only policies are graded separately. They cannot lock anyone
            out today, and calling them Critical teaches operators that Critical
            means nothing. They are exactly what wants fixing before enablement.
        .PARAMETER Policy
            Conditional Access policies as Microsoft Graph returns them.
        .PARAMETER BreakGlassAccount
            The accounts that must never lose access, each with its id, its group
            and role memberships, and what it can actually present at sign-in.
        .EXAMPLE
            Test-LockoutRisk -Policy $policies -BreakGlassAccount $accounts |
                Where-Object Severity -eq 'Critical'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Policy,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$BreakGlassAccount
    )

    foreach ($account in $BreakGlassAccount) {
        $accountName = [string](Get-OptionalProperty $account 'displayName')
        if ([string]::IsNullOrWhiteSpace($accountName)) {
            $accountName = [string](Get-OptionalProperty $account 'id')
        }

        foreach ($item in $Policy) {
            $policyName = [string](Get-OptionalProperty $item 'displayName')
            $state = [string](Get-OptionalProperty $item 'state')
            if ([string]::IsNullOrWhiteSpace($state)) { $state = 'enabled' }

            # A disabled policy is inert. It is still worth saying out loud that
            # it exists, because "we turned it off" is a decision someone can
            # quietly reverse.
            if ($state -eq 'disabled') { continue }

            $scope = Test-PolicyScope -Policy $item -Account $account
            if (-not $scope.InScope) { continue }

            # @() at the call site, not a comma inside the function. Wrapping an
            # empty array on the way out produces a one-element array holding an
            # empty array, so the count is 1 and every policy looks in scope.
            $surfaces = @(Test-PolicyTargetsRecovery -Policy $item)
            if ($surfaces.Count -eq 0) { continue }

            $grant = Test-GrantSatisfiable -GrantControls (Get-OptionalProperty $item 'grantControls') -Account $account
            if ($grant.Satisfiable) { continue }

            $severity = if ($state -eq 'enabledForReportingButNotEnforced') { 'High' } else { 'Critical' }
            $tense = if ($severity -eq 'High') { 'would be locked out if this policy were enforced' } else { 'is locked out' }

            [pscustomobject]@{
                Severity    = $severity
                Account     = $accountName
                Policy      = $policyName
                State       = $state
                Surfaces    = $surfaces
                IncludedBy  = $scope.IncludedBy
                Unevaluated = $grant.Unevaluated
                Detail      = "$accountName $tense of $($surfaces -join ', ') by '$policyName' ($($scope.IncludedBy)) and cannot satisfy its grant controls."
            }
        }
    }
}

function Get-EffectiveVerdict {
    <#
        .SYNOPSIS
            Derives what would actually happen at sign-in from a What If result.
        .DESCRIPTION
            The evaluate API answers a narrower question than people assume. It
            reports, per policy, whether that policy applies -- not what the
            sign-in outcome is. Two things follow, and both are easy to get wrong:

            A report-only policy returns policyApplies = true. It applies in the
            sense the API means, and enforces nothing. Folding those into the
            verdict produces a confident prediction of "blocked" for a sign-in
            that in reality succeeds.

            analysisReasons = notEnoughInformation means the service declined to
            judge, usually because the request omitted a condition the policy
            tests. That is not the same as "does not apply". Treating it as a
            pass is how an evaluation reports success about something it never
            evaluated, so it surfaces here as Inconclusive and fails the
            comparison rather than quietly counting as agreement.
        .OUTPUTS
            A record carrying the verdict, the policies behind it, and anything
            the service could not decide.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Result,
        [switch]$TreatReportOnlyAsEnforced
    )

    $inconclusive = @()
    $enforcing = @()
    $reportOnly = @()

    foreach ($item in $Result) {
        $name = [string](Get-OptionalProperty $item 'displayName')
        $applies = Get-OptionalProperty $item 'policyApplies'
        $reason = [string](Get-OptionalProperty $item 'analysisReasons')
        $state = [string](Get-OptionalProperty $item 'state')

        if ($reason -in @('notEnoughInformation', 'invalidCondition', 'invalidPolicy')) {
            $inconclusive += "$name ($reason)"
            continue
        }
        if (-not $applies) { continue }

        if ($state -eq 'enabledForReportingButNotEnforced') {
            $reportOnly += $name
            # Two different questions. Without the switch: what happens to this
            # sign-in today, where a report-only policy changes nothing. With it:
            # what would happen if these were enforced, which is the question
            # worth answering while there is still time to fix the answer.
            if ($TreatReportOnlyAsEnforced) { $enforcing += $item }
        }
        else { $enforcing += $item }
    }

    if ($inconclusive.Count) {
        return [pscustomobject]@{
            Verdict      = 'Inconclusive'
            Applied      = @($enforcing | ForEach-Object { [string](Get-OptionalProperty $_ 'displayName') })
            ReportOnly   = $reportOnly
            Inconclusive = $inconclusive
        }
    }

    $verdict = 'Granted'
    $controls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($item in $enforcing) {
        $set = ConvertTo-Set (Get-OptionalProperty (Get-OptionalProperty $item 'grantControls') 'builtInControls')
        foreach ($control in $set) { [void]$controls.Add($control) }
        if ($null -ne (Get-OptionalProperty (Get-OptionalProperty $item 'grantControls') 'authenticationStrength')) {
            [void]$controls.Add('mfa')
        }
    }

    if ($controls.Contains('block')) { $verdict = 'Blocked' }
    elseif ($controls.Contains('mfa')) { $verdict = 'MfaRequired' }
    elseif ($controls.Contains('compliantDevice') -or $controls.Contains('domainJoinedDevice')) { $verdict = 'CompliantDeviceRequired' }

    [pscustomobject]@{
        Verdict      = $verdict
        Applied      = @($enforcing | ForEach-Object { [string](Get-OptionalProperty $_ 'displayName') })
        ReportOnly   = $reportOnly
        Inconclusive = @()
    }
}

function Compare-EvaluationToMatrix {
    <#
        .SYNOPSIS
            Checks the directory's own verdict against the scenario matrix.
        .DESCRIPTION
            The matrix states, for each sign-in scenario, what should happen and
            why. This asks Entra what would happen and reports where the two
            disagree. A scenario the service could not evaluate counts as a
            failure, not a pass.
        .PARAMETER Scenario
            Declared scenarios, each with a name, an expected verdict and a why.
        .PARAMETER Evaluation
            The What If results for each scenario, keyed by scenario name.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Scenario,
        [Parameter(Mandatory)][hashtable]$Evaluation,
        [switch]$TreatReportOnlyAsEnforced
    )

    foreach ($item in $Scenario) {
        $name = [string](Get-OptionalProperty $item 'name')
        $expected = [string](Get-OptionalProperty $item 'expect')

        if (-not $Evaluation.ContainsKey($name)) {
            [pscustomobject]@{
                Scenario = $name; Expected = $expected; Actual = 'NotEvaluated'
                Match = $false; Applied = @(); ReportOnly = @()
                Detail = "No evaluation was returned for '$name'."
            }
            continue
        }

        $actual = Get-EffectiveVerdict -Result @($Evaluation[$name]) -TreatReportOnlyAsEnforced:$TreatReportOnlyAsEnforced
        $match = ($actual.Verdict -eq $expected)

        $detail = if ($match) {
            "Entra agrees: $expected."
        }
        elseif ($actual.Verdict -eq 'Inconclusive') {
            "Entra could not decide: $($actual.Inconclusive -join '; '). Expected $expected."
        }
        else {
            "Expected $expected, Entra says $($actual.Verdict) via $($actual.Applied -join ', ')."
        }

        [pscustomobject]@{
            Scenario   = $name
            Expected   = $expected
            Actual     = $actual.Verdict
            Match      = $match
            Applied    = $actual.Applied
            ReportOnly = $actual.ReportOnly
            Detail     = $detail
        }
    }
}

function ConvertTo-AddressKey {
    <#
        .SYNOPSIS
            Normalises a proxyAddresses entry for comparison.
        .DESCRIPTION
            proxyAddresses carries the type as a prefix, and the case of that
            prefix is meaningful: SMTP: is the primary address, smtp: a secondary
            one. The address itself is not case sensitive. Comparing the raw
            strings therefore misses the most common real collision of all, where
            one directory holds an address as primary and the other holds the same
            address as a secondary alias.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$Address)

    $value = $Address.Trim()
    $separator = $value.IndexOf(':')
    if ($separator -lt 0) { return "smtp:$($value.ToLowerInvariant())" }

    $type = $value.Substring(0, $separator).ToLowerInvariant()
    $rest = $value.Substring($separator + 1).ToLowerInvariant()
    return "${type}:${rest}"
}

function Find-MergeCollision {
    <#
        .SYNOPSIS
            Finds the identity conflicts that would fail a tenant merge.
        .DESCRIPTION
            Run before a consolidation, against exports of both directories. The
            distinction that matters is between two accounts that clash and two
            accounts that are the same person: the first needs one of them
            renamed, the second needs them merged, and treating either as the
            other causes an outage or a privacy incident respectively. Sameness is
            judged on a stable anchor -- employeeId, or the on-premises immutable
            ID -- never on a display name.
        .PARAMETER SourceUser
            Users from the directory being absorbed.
        .PARAMETER TargetUser
            Users from the directory that survives.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$SourceUser,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$TargetUser
    )

    $byUpn = @{}
    $byAddress = @{}
    $byAnchor = @{}

    foreach ($user in $TargetUser) {
        $upn = [string](Get-OptionalProperty $user 'userPrincipalName')
        if ($upn) { $byUpn[$upn.ToLowerInvariant()] = $user }

        foreach ($address in @(Get-OptionalProperty $user 'proxyAddresses')) {
            if ($address) { $byAddress[(ConvertTo-AddressKey $address)] = $user }
        }

        foreach ($field in 'employeeId', 'onPremisesImmutableId') {
            $anchor = [string](Get-OptionalProperty $user $field)
            if ($anchor) { $byAnchor["${field}:$($anchor.ToLowerInvariant())"] = $user }
        }
    }

    foreach ($user in $SourceUser) {
        $upn = [string](Get-OptionalProperty $user 'userPrincipalName')
        $sourceName = if ($upn) { $upn } else { [string](Get-OptionalProperty $user 'displayName') }

        # Same person first. A shared anchor means these two records describe one
        # human, and every address they have in common is expected rather than a
        # conflict to be renamed away.
        $samePerson = $null
        foreach ($field in 'employeeId', 'onPremisesImmutableId') {
            $anchor = [string](Get-OptionalProperty $user $field)
            if ($anchor -and $byAnchor.ContainsKey("${field}:$($anchor.ToLowerInvariant())")) {
                $samePerson = $byAnchor["${field}:$($anchor.ToLowerInvariant())"]
                break
            }
        }

        if ($samePerson) {
            [pscustomobject]@{
                Kind       = 'SameIdentity'
                Source     = $sourceName
                Target     = [string](Get-OptionalProperty $samePerson 'userPrincipalName')
                Attribute  = 'employeeId/onPremisesImmutableId'
                Value      = ''
                Resolution = 'Merge these two records. They share a stable anchor, so they are one person with an account in each directory.'
            }
            continue
        }

        if ($upn -and $byUpn.ContainsKey($upn.ToLowerInvariant())) {
            [pscustomobject]@{
                Kind       = 'UpnCollision'
                Source     = $sourceName
                Target     = [string](Get-OptionalProperty $byUpn[$upn.ToLowerInvariant()] 'userPrincipalName')
                Attribute  = 'userPrincipalName'
                Value      = $upn
                Resolution = 'Two different people hold the same sign-in name. Rename the source account before the cutover; it cannot be resolved during it.'
            }
        }

        foreach ($address in @(Get-OptionalProperty $user 'proxyAddresses')) {
            if (-not $address) { continue }
            $key = ConvertTo-AddressKey $address
            if (-not $byAddress.ContainsKey($key)) { continue }

            [pscustomobject]@{
                Kind       = 'AddressCollision'
                Source     = $sourceName
                Target     = [string](Get-OptionalProperty $byAddress[$key] 'userPrincipalName')
                Attribute  = 'proxyAddresses'
                Value      = $key
                Resolution = 'The same mail address is claimed by two different people. Remove it from the source account; mail delivery is ambiguous until it is gone.'
            }
        }
    }
}

function Get-SyncErrorRemediation {
    <#
        .SYNOPSIS
            Classifies an Entra Connect sync error and says what to do about it.
        .DESCRIPTION
            Each class carries an AutoRemediable flag, and the flag is the point
            of the function. A duplicate address between two records of the same
            person is a safe, mechanical fix. An invalid soft match is the same
            error text about two records that may be different people, and
            "fixing" it automatically welds one person's mailbox onto another's
            account. The two must never share a code path.
        .PARAMETER SyncError
            Errors as the Entra Connect health API reports them.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object]$SyncError
    )

    process {
        $code = [string](Get-OptionalProperty $SyncError 'errorCode')
        $attribute = [string](Get-OptionalProperty $SyncError 'attributeName')
        $object = [string](Get-OptionalProperty $SyncError 'objectId')
        $sameAnchor = [bool](Get-OptionalProperty $SyncError 'anchorsMatch')

        $class, $auto, $action = switch -Regex ($code) {
            '^AttributeValueMustBeUnique$|^DuplicateAttributes$' {
                if ($sameAnchor) {
                    @('DuplicateAttribute', $true,
                      "Remove the duplicate '$attribute' from the on-premises object. Both records share a stable anchor, so this is one person and the value belongs on the surviving record only.")
                }
                else {
                    @('DuplicateAttribute', $false,
                      "Two objects with different anchors claim the same '$attribute'. Decide which is correct with the business before changing either; this is not a mechanical fix.")
                }
                break
            }
            '^InvalidSoftMatch$' {
                # Deliberately never auto-remediable, whatever the anchors say.
                @('InvalidSoftMatch', $false,
                  "A cloud object was matched to '$object' on a mail attribute rather than an anchor. Confirm they are the same person before doing anything; resolving this wrongly merges two identities and cannot be cleanly undone.")
                break
            }
            '^LargeObject$' {
                if ($attribute -eq 'userCertificate') {
                    @('LargeObject', $false,
                      "The '$attribute' on '$object' exceeds the sync size limit. Clearing certificates breaks certificate-based authentication, so prune expired entries deliberately rather than truncating.")
                }
                else {
                    @('LargeObject', $true,
                      "Clear the oversized '$attribute' on '$object'. The value is cosmetic and is recoverable from the on-premises object.")
                }
                break
            }
            '^(Identity)?DataValidationFailed$' {
                @('InvalidData', $true,
                  "The '$attribute' on '$object' is not a legal value. Correct it on-premises to use a verified domain suffix and no illegal characters, then force a delta sync.")
                break
            }
            '^FederatedDomainChangeError$' {
                @('FederatedDomain', $false,
                  "The object's domain suffix moved between federated and managed authentication. This is a tenant-level change and must not be resolved per object.")
                break
            }
            default {
                # An unknown code is not a clean object. Saying so is the whole
                # value of this branch.
                @('Unclassified', $false,
                  "Sync error code '$code' is not recognised by this module. Treat it as unresolved and read the raw error rather than assuming it is benign.")
            }
        }

        [pscustomobject]@{
            ObjectId       = $object
            ErrorCode      = $code
            Class          = $class
            Attribute      = $attribute
            AutoRemediable = $auto
            Action         = $action
        }
    }
}

function Get-PrivilegedAccessFinding {
    <#
        .SYNOPSIS
            Reviews who holds privileged directory roles and how.
        .DESCRIPTION
            Standing assignment to a privileged role is the finding, not role
            membership itself. Two break-glass accounts are supposed to hold
            permanent Global Administrator -- that is what makes them
            break-glass -- so reporting them as violations trains the reader to
            dismiss the whole report. They are graded Info and counted, and the
            count being wrong in either direction is itself a finding.
        .PARAMETER Assignment
            Role assignments, each naming the principal, the role, and whether it
            is permanent or activated through PIM.
        .PARAMETER BreakGlassId
            The object IDs expected to hold standing Global Administrator.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Assignment,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$BreakGlassId
    )

    $breakGlass = ConvertTo-Set $BreakGlassId
    $standingGlobalAdmins = @()
    $globalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

    foreach ($item in $Assignment) {
        $principal = [string](Get-OptionalProperty $item 'principalId')
        $name = [string](Get-OptionalProperty $item 'principalDisplayName')
        if (-not $name) { $name = $principal }
        $roleId = [string](Get-OptionalProperty $item 'roleDefinitionId')
        $roleName = [string](Get-OptionalProperty $item 'roleDisplayName')
        if (-not $roleName -and $script:RecoveryRoles.ContainsKey($roleId)) {
            $roleName = $script:RecoveryRoles[$roleId]
        }
        $permanent = [bool](Get-OptionalProperty $item 'isPermanent')
        $isGuest = [bool](Get-OptionalProperty $item 'isGuest')
        $hasMfa = [bool](Get-OptionalProperty $item 'hasMfaMethod')
        $privileged = $script:RecoveryRoles.ContainsKey($roleId)

        if ($privileged -and $permanent -and $roleId -eq $globalAdminRoleId) {
            $standingGlobalAdmins += $principal
        }

        if ($breakGlass.Contains($principal)) {
            [pscustomobject]@{
                Severity  = 'Info'
                Principal = $name
                Role      = $roleName
                Detail    = "$name holds standing $roleName as a designated break-glass account. This is intended."
            }
            continue
        }

        if ($isGuest -and $privileged) {
            [pscustomobject]@{
                Severity  = 'Critical'
                Principal = $name
                Role      = $roleName
                Detail    = "$name is an external guest holding $roleName. Privileged roles should be held by accounts this directory governs."
            }
        }

        if ($privileged -and -not $hasMfa) {
            [pscustomobject]@{
                Severity  = 'Critical'
                Principal = $name
                Role      = $roleName
                Detail    = "$name holds $roleName with no registered strong authentication method."
            }
        }

        if ($privileged -and $permanent) {
            [pscustomobject]@{
                Severity  = 'High'
                Principal = $name
                Role      = $roleName
                Detail    = "$name holds $roleName permanently. Privileged roles should be activated through PIM for the window they are needed."
            }
        }
    }

    $count = @($standingGlobalAdmins | Sort-Object -Unique).Count
    if ($count -ne 2) {
        [pscustomobject]@{
            Severity  = 'High'
            Principal = '(tenant)'
            Role      = 'Global Administrator'
            Detail    = "$count accounts hold standing Global Administrator. The convention is exactly two break-glass accounts: fewer risks a tenant nobody can recover, more is standing privilege that was never reviewed."
        }
    }
}

Export-ModuleMember -Function Test-PolicyScope, Test-PolicyTargetsRecovery,
    Test-GrantSatisfiable, Test-LockoutRisk, Get-EffectiveVerdict,
    Compare-EvaluationToMatrix, Find-MergeCollision, ConvertTo-AddressKey,
    Get-SyncErrorRemediation, Get-PrivilegedAccessFinding
