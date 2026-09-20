#requires -Version 7.0
#requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

BeforeAll {
    $modulePath = [System.IO.Path]::Combine($PSScriptRoot, '..', 'module', 'HybridIdentity', 'HybridIdentity.psm1')
    Import-Module $modulePath -Force -ErrorAction Stop

    $script:BreakGlassId = '11111111-1111-1111-1111-111111111111'
    $script:BreakGlassGroup = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
    $script:GlobalAdminRole = '62e90394-69f5-4237-9190-012177145e10'
    $script:AzureManagement = '797f4846-ba00-4fd7-ba43-dac1f8f63013'

    function New-BreakGlass {
        param([switch]$WithMfa, [switch]$OnCompliantDevice)
        [pscustomobject]@{
            id                     = $script:BreakGlassId
            displayName            = 'break-glass-01'
            groupIds               = @($script:BreakGlassGroup)
            roleIds                = @($script:GlobalAdminRole)
            hasMfaMethod           = [bool]$WithMfa
            usesCompliantDevice    = [bool]$OnCompliantDevice
            usesDomainJoinedDevice = $false
            usesApprovedClientApp  = $false
        }
    }

    function New-Policy {
        param(
            [string]$Name = 'policy',
            [string]$State = 'enabled',
            [object]$Users = $null,
            [object]$Applications = $null,
            [object]$GrantControls = $null
        )
        if ($null -eq $Users) { $Users = [pscustomobject]@{ includeUsers = @('All') } }
        if ($null -eq $Applications) { $Applications = [pscustomobject]@{ includeApplications = @('All') } }
        [pscustomobject]@{
            displayName   = $Name
            state         = $State
            conditions    = [pscustomobject]@{ users = $Users; applications = $Applications }
            grantControls = $GrantControls
        }
    }

    function New-Grant {
        param([string[]]$Controls, [string]$Operator = 'OR')
        [pscustomobject]@{ builtInControls = $Controls; operator = $Operator }
    }
}

Describe 'Test-PolicyScope' {
    It 'includes an account caught by includeUsers All' {
        $result = Test-PolicyScope -Policy (New-Policy) -Account (New-BreakGlass)
        $result.InScope | Should -BeTrue
        $result.IncludedBy | Should -Be 'every user in the tenant'
    }

    It 'excludes an account named directly in excludeUsers' {
        $users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @($script:BreakGlassId) }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
    }

    # The exclusion most tenants actually use, and the one a naive checker misses.
    It 'excludes an account through its group rather than its object ID' {
        $users = [pscustomobject]@{ includeUsers = @('All'); excludeGroups = @($script:BreakGlassGroup) }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
        $result.ExcludedBy | Should -Match 'excluded group'
    }

    It 'excludes an account through a directory role' {
        $users = [pscustomobject]@{ includeUsers = @('All'); excludeRoles = @($script:GlobalAdminRole) }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
    }

    It 'lets exclusion win over an explicit inclusion' {
        $users = [pscustomobject]@{
            includeUsers  = @($script:BreakGlassId)
            excludeGroups = @($script:BreakGlassGroup)
        }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
    }

    It 'treats object IDs case-insensitively' {
        $users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @($script:BreakGlassId.ToUpperInvariant()) }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
    }

    It 'reports out of scope when the account is in no include set' {
        $users = [pscustomobject]@{ includeUsers = @('99999999-9999-9999-9999-999999999999') }
        $result = Test-PolicyScope -Policy (New-Policy -Users $users) -Account (New-BreakGlass)
        $result.InScope | Should -BeFalse
        $result.IncludedBy | Should -BeNullOrEmpty
    }
}

Describe 'Test-PolicyTargetsRecovery' {
    It 'reports every recovery surface for an All applications policy' {
        $surfaces = @(Test-PolicyTargetsRecovery -Policy (New-Policy))
        $surfaces.Count | Should -BeGreaterThan 0
        $surfaces | Should -Contain 'Azure portal'
    }

    It 'reports nothing for a policy scoped to one line-of-business app' {
        $apps = [pscustomobject]@{ includeApplications = @('99999999-9999-9999-9999-999999999999') }
        $surfaces = @(Test-PolicyTargetsRecovery -Policy (New-Policy -Applications $apps))
        $surfaces.Count | Should -Be 0
    }

    It 'honours an excluded recovery surface inside an All applications policy' {
        $apps = [pscustomobject]@{
            includeApplications = @('All')
            excludeApplications = @($script:AzureManagement)
        }
        $surfaces = @(Test-PolicyTargetsRecovery -Policy (New-Policy -Applications $apps))
        $surfaces | Should -Not -Contain 'Windows Azure Service Management API'
    }

    It 'recognises a recovery surface named explicitly' {
        $apps = [pscustomobject]@{ includeApplications = @($script:AzureManagement) }
        $surfaces = @(Test-PolicyTargetsRecovery -Policy (New-Policy -Applications $apps))
        $surfaces | Should -Contain 'Windows Azure Service Management API'
    }
}

Describe 'Test-GrantSatisfiable' {
    It 'never satisfies a block control, whatever the operator says' {
        $result = Test-GrantSatisfiable -GrantControls (New-Grant -Controls @('block', 'mfa') -Operator 'OR') -Account (New-BreakGlass -WithMfa)
        $result.Satisfiable | Should -BeFalse
    }

    It 'satisfies MFA when the account has a registered method' {
        $result = Test-GrantSatisfiable -GrantControls (New-Grant -Controls @('mfa')) -Account (New-BreakGlass -WithMfa)
        $result.Satisfiable | Should -BeTrue
    }

    It 'refuses MFA for a break-glass account with no registered method' {
        $result = Test-GrantSatisfiable -GrantControls (New-Grant -Controls @('mfa')) -Account (New-BreakGlass)
        $result.Satisfiable | Should -BeFalse
    }

    It 'lets any one control through under OR' {
        $grant = New-Grant -Controls @('mfa', 'compliantDevice') -Operator 'OR'
        $result = Test-GrantSatisfiable -GrantControls $grant -Account (New-BreakGlass -OnCompliantDevice)
        $result.Satisfiable | Should -BeTrue
    }

    It 'requires every control under AND' {
        $grant = New-Grant -Controls @('mfa', 'compliantDevice') -Operator 'AND'
        $result = Test-GrantSatisfiable -GrantControls $grant -Account (New-BreakGlass -OnCompliantDevice)
        $result.Satisfiable | Should -BeFalse
    }

    It 'treats a policy with no grant controls as harmless' {
        $result = Test-GrantSatisfiable -GrantControls $null -Account (New-BreakGlass)
        $result.Satisfiable | Should -BeTrue
    }

    # A check that cannot judge something must say so rather than pass it.
    It 'refuses an unrecognised control and reports that it could not judge it' {
        $result = Test-GrantSatisfiable -GrantControls (New-Grant -Controls @('someFutureControl')) -Account (New-BreakGlass -WithMfa)
        $result.Satisfiable | Should -BeFalse
        $result.Unevaluated | Should -Match 'not recognised'
    }

    It 'refuses an authentication strength the account facts do not cover' {
        $grant = [pscustomobject]@{
            builtInControls       = @()
            operator              = 'AND'
            authenticationStrength = [pscustomobject]@{ displayName = 'Phishing-resistant MFA' }
        }
        $result = Test-GrantSatisfiable -GrantControls $grant -Account (New-BreakGlass -WithMfa)
        $result.Satisfiable | Should -BeFalse
        $result.Unevaluated | Should -Match 'Phishing-resistant MFA'
    }

    It 'accepts an authentication strength the account states it satisfies' {
        $grant = [pscustomobject]@{
            builtInControls       = @()
            operator              = 'AND'
            authenticationStrength = [pscustomobject]@{ displayName = 'Phishing-resistant MFA' }
        }
        $account = New-BreakGlass -WithMfa
        $account | Add-Member -NotePropertyName satisfiesAuthenticationStrength -NotePropertyValue $true
        (Test-GrantSatisfiable -GrantControls $grant -Account $account).Satisfiable | Should -BeTrue
    }
}

Describe 'Test-LockoutRisk' {
    It 'reports a tenant-wide MFA requirement as Critical' {
        $policy = New-Policy -Name 'Require MFA for all users' -GrantControls (New-Grant -Controls @('mfa'))
        $findings = @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass))
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'Critical'
    }

    It 'stays silent when break-glass is excluded by group' {
        $users = [pscustomobject]@{ includeUsers = @('All'); excludeGroups = @($script:BreakGlassGroup) }
        $policy = New-Policy -Name 'Block legacy auth' -Users $users -GrantControls (New-Grant -Controls @('block'))
        @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass)).Count | Should -Be 0
    }

    It 'stays silent for a policy that blocks one line-of-business app' {
        $apps = [pscustomobject]@{ includeApplications = @('99999999-9999-9999-9999-999999999999') }
        $policy = New-Policy -Name 'Block Dropbox' -Applications $apps -GrantControls (New-Grant -Controls @('block'))
        @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass)).Count | Should -Be 0
    }

    It 'grades an identical report-only policy High rather than Critical' {
        $policy = New-Policy -Name 'Pilot' -State 'enabledForReportingButNotEnforced' -GrantControls (New-Grant -Controls @('mfa'))
        $findings = @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass))
        $findings.Count | Should -Be 1
        $findings[0].Severity | Should -Be 'High'
        $findings[0].Detail | Should -Match 'would be locked out'
    }

    It 'ignores a disabled policy entirely' {
        $policy = New-Policy -Name 'Old' -State 'disabled' -GrantControls (New-Grant -Controls @('block'))
        @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass)).Count | Should -Be 0
    }

    It 'stays silent when the account can satisfy the requirement' {
        $policy = New-Policy -Name 'Require MFA' -GrantControls (New-Grant -Controls @('mfa'))
        @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @(New-BreakGlass -WithMfa)).Count | Should -Be 0
    }

    It 'reports each affected account separately' {
        $second = New-BreakGlass
        $second.id = '22222222-2222-2222-2222-222222222222'
        $second.displayName = 'break-glass-02'
        $policy = New-Policy -Name 'Require MFA' -GrantControls (New-Grant -Controls @('mfa'))
        @(Test-LockoutRisk -Policy @($policy) -BreakGlassAccount @((New-BreakGlass), $second)).Count | Should -Be 2
    }

    It 'accepts an empty policy set without error' {
        @(Test-LockoutRisk -Policy @() -BreakGlassAccount @(New-BreakGlass)).Count | Should -Be 0
    }
}

Describe 'Get-EffectiveVerdict' {
    It 'reports Granted when nothing applies' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'P'; policyApplies = $false; analysisReasons = 'users'; state = 'enabled' })
        $result.Verdict | Should -Be 'Granted'
    }

    It 'reports Blocked when an enforced policy blocks' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'P'; policyApplies = $true; analysisReasons = 'notSet'; state = 'enabled'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } })
        $result.Verdict | Should -Be 'Blocked'
    }

    # policyApplies is true for report-only policies. Counting them produces a
    # confident prediction of Blocked for a sign-in that actually succeeds.
    It 'does not let a report-only policy change the verdict' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'Pilot'; policyApplies = $true; analysisReasons = 'notSet'
                state = 'enabledForReportingButNotEnforced'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } })
        $result.Verdict | Should -Be 'Granted'
        $result.ReportOnly | Should -Contain 'Pilot'
    }

    # The predictive question: not what happens today, but what would happen if
    # these report-only policies were enforced. Answering it is the only way to
    # find a lockout while it is still cheap to fix.
    It 'counts a report-only policy when asked what enforcement would do' {
        $result = Get-EffectiveVerdict -TreatReportOnlyAsEnforced -Result @(
            [pscustomobject]@{ displayName = 'Pilot'; policyApplies = $true; analysisReasons = 'notSet'
                state = 'enabledForReportingButNotEnforced'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } })
        $result.Verdict | Should -Be 'Blocked'
        $result.ReportOnly | Should -Contain 'Pilot'
    }

    It 'still ignores a disabled policy in predictive mode' {
        $result = Get-EffectiveVerdict -TreatReportOnlyAsEnforced -Result @(
            [pscustomobject]@{ displayName = 'Off'; policyApplies = $false; analysisReasons = 'policyNotEnabled'; state = 'disabled' })
        $result.Verdict | Should -Be 'Granted'
    }

    It 'reports Blocked when block and mfa both apply' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'A'; policyApplies = $true; analysisReasons = 'notSet'; state = 'enabled'
                grantControls = [pscustomobject]@{ builtInControls = @('mfa') } },
            [pscustomobject]@{ displayName = 'B'; policyApplies = $true; analysisReasons = 'notSet'; state = 'enabled'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } })
        $result.Verdict | Should -Be 'Blocked'
    }

    It 'treats an authentication strength requirement as MFA' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'A'; policyApplies = $true; analysisReasons = 'notSet'; state = 'enabled'
                grantControls = [pscustomobject]@{ builtInControls = @(); authenticationStrength = [pscustomobject]@{ displayName = 'Phishing-resistant MFA' } } })
        $result.Verdict | Should -Be 'MfaRequired'
    }

    # The service declining to judge is not the same as the policy not applying.
    It 'reports Inconclusive when the service had too little information' {
        $result = Get-EffectiveVerdict -Result @(
            [pscustomobject]@{ displayName = 'P'; policyApplies = $false; analysisReasons = 'notEnoughInformation'; state = 'enabled' })
        $result.Verdict | Should -Be 'Inconclusive'
        $result.Inconclusive | Should -Not -BeNullOrEmpty
    }
}

Describe 'Compare-EvaluationToMatrix' {
    It 'matches when Entra agrees with the declared expectation' {
        $scenario = @([pscustomobject]@{ name = 'admin from untrusted network'; expect = 'Blocked'; why = 'test' })
        $evaluation = @{ 'admin from untrusted network' = @(
            [pscustomobject]@{ displayName = 'P'; policyApplies = $true; analysisReasons = 'notSet'; state = 'enabled'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } }) }
        $result = @(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation $evaluation)
        $result[0].Match | Should -BeTrue
    }

    It 'fails when Entra disagrees' {
        $scenario = @([pscustomobject]@{ name = 's'; expect = 'Blocked'; why = 'test' })
        $evaluation = @{ 's' = @([pscustomobject]@{ displayName = 'P'; policyApplies = $false; analysisReasons = 'users'; state = 'enabled' }) }
        $result = @(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation $evaluation)
        $result[0].Match | Should -BeFalse
        $result[0].Actual | Should -Be 'Granted'
    }

    It 'fails an inconclusive evaluation rather than counting it as agreement' {
        $scenario = @([pscustomobject]@{ name = 's'; expect = 'Granted'; why = 'test' })
        $evaluation = @{ 's' = @([pscustomobject]@{ displayName = 'P'; policyApplies = $false; analysisReasons = 'notEnoughInformation'; state = 'enabled' }) }
        $result = @(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation $evaluation)
        $result[0].Match | Should -BeFalse
        $result[0].Detail | Should -Match 'could not decide'
    }

    It 'passes the predictive mode through to the verdict' {
        $scenario = @([pscustomobject]@{ name = 's'; expect = 'Blocked'; why = 'test' })
        $evaluation = @{ 's' = @(
            [pscustomobject]@{ displayName = 'Pilot'; policyApplies = $true; analysisReasons = 'notSet'
                state = 'enabledForReportingButNotEnforced'
                grantControls = [pscustomobject]@{ builtInControls = @('block') } }) }

        # The same evaluation, read two ways: nothing is enforced today, and
        # everything would be on promotion.
        (@(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation $evaluation)[0]).Match | Should -BeFalse
        (@(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation $evaluation -TreatReportOnlyAsEnforced)[0]).Match | Should -BeTrue
    }

    It 'fails a scenario that was never evaluated' {
        $scenario = @([pscustomobject]@{ name = 'missing'; expect = 'Granted'; why = 'test' })
        $result = @(Compare-EvaluationToMatrix -Scenario $scenario -Evaluation @{})
        $result[0].Match | Should -BeFalse
        $result[0].Actual | Should -Be 'NotEvaluated'
    }
}

Describe 'ConvertTo-AddressKey' {
    It 'makes a primary and a secondary form of one address compare equal' {
        (ConvertTo-AddressKey 'SMTP:Ziyad@Example.com') | Should -Be (ConvertTo-AddressKey 'smtp:ziyad@example.com')
    }

    It 'keeps different address types apart' {
        (ConvertTo-AddressKey 'smtp:a@b.com') | Should -Not -Be (ConvertTo-AddressKey 'sip:a@b.com')
    }

    It 'assumes smtp for a bare address' {
        (ConvertTo-AddressKey 'a@b.com') | Should -Be 'smtp:a@b.com'
    }
}

Describe 'Find-MergeCollision' {
    It 'reports a UPN held by two different people' {
        $source = @([pscustomobject]@{ userPrincipalName = 'jsmith@contoso.com' })
        $target = @([pscustomobject]@{ userPrincipalName = 'jsmith@contoso.com' })
        $result = @(Find-MergeCollision -SourceUser $source -TargetUser $target)
        $result.Kind | Should -Contain 'UpnCollision'
    }

    # The case a raw string comparison misses.
    It 'reports an address held as primary in one directory and secondary in the other' {
        $source = @([pscustomobject]@{ userPrincipalName = 'a@x.com'; proxyAddresses = @('SMTP:Sales@Contoso.com') })
        $target = @([pscustomobject]@{ userPrincipalName = 'b@y.com'; proxyAddresses = @('smtp:sales@contoso.com') })
        $result = @(Find-MergeCollision -SourceUser $source -TargetUser $target)
        $result.Kind | Should -Contain 'AddressCollision'
    }

    It 'calls a shared employeeId one person rather than a collision' {
        $source = @([pscustomobject]@{ userPrincipalName = 'z.uqdah@old.com'; employeeId = 'E42'; proxyAddresses = @('smtp:z@shared.com') })
        $target = @([pscustomobject]@{ userPrincipalName = 'ziyad@new.com'; employeeId = 'E42'; proxyAddresses = @('smtp:z@shared.com') })
        $result = @(Find-MergeCollision -SourceUser $source -TargetUser $target)
        $result.Count | Should -Be 1
        $result[0].Kind | Should -Be 'SameIdentity'
        $result[0].Resolution | Should -Match 'Merge'
    }

    It 'finds nothing between two disjoint directories' {
        $source = @([pscustomobject]@{ userPrincipalName = 'a@x.com'; proxyAddresses = @('smtp:a@x.com') })
        $target = @([pscustomobject]@{ userPrincipalName = 'b@y.com'; proxyAddresses = @('smtp:b@y.com') })
        @(Find-MergeCollision -SourceUser $source -TargetUser $target).Count | Should -Be 0
    }

    It 'matches UPNs regardless of case' {
        $source = @([pscustomobject]@{ userPrincipalName = 'JSmith@Contoso.com' })
        $target = @([pscustomobject]@{ userPrincipalName = 'jsmith@contoso.com' })
        @(Find-MergeCollision -SourceUser $source -TargetUser $target).Kind | Should -Contain 'UpnCollision'
    }
}

Describe 'Get-SyncErrorRemediation' {
    It 'will auto-remediate a duplicate address between records of the same person' {
        $result = [pscustomobject]@{ errorCode = 'AttributeValueMustBeUnique'; attributeName = 'proxyAddresses'; objectId = 'u1'; anchorsMatch = $true } |
            Get-SyncErrorRemediation
        $result.AutoRemediable | Should -BeTrue
    }

    It 'will not auto-remediate the same error between records with different anchors' {
        $result = [pscustomobject]@{ errorCode = 'AttributeValueMustBeUnique'; attributeName = 'proxyAddresses'; objectId = 'u1'; anchorsMatch = $false } |
            Get-SyncErrorRemediation
        $result.AutoRemediable | Should -BeFalse
    }

    # Auto-resolving this merges two people's identities. It is never safe.
    It 'never auto-remediates an invalid soft match, even with matching anchors' {
        $result = [pscustomobject]@{ errorCode = 'InvalidSoftMatch'; attributeName = 'mail'; objectId = 'u1'; anchorsMatch = $true } |
            Get-SyncErrorRemediation
        $result.Class | Should -Be 'InvalidSoftMatch'
        $result.AutoRemediable | Should -BeFalse
    }

    It 'will clear an oversized thumbnail but not an oversized certificate' {
        $photo = [pscustomobject]@{ errorCode = 'LargeObject'; attributeName = 'thumbnailPhoto'; objectId = 'u1'; anchorsMatch = $false } | Get-SyncErrorRemediation
        $cert = [pscustomobject]@{ errorCode = 'LargeObject'; attributeName = 'userCertificate'; objectId = 'u1'; anchorsMatch = $false } | Get-SyncErrorRemediation
        $photo.AutoRemediable | Should -BeTrue
        $cert.AutoRemediable | Should -BeFalse
    }

    It 'refuses to classify an unknown code as benign' {
        $result = [pscustomobject]@{ errorCode = 'SomethingNew'; attributeName = ''; objectId = 'u1'; anchorsMatch = $true } |
            Get-SyncErrorRemediation
        $result.Class | Should -Be 'Unclassified'
        $result.AutoRemediable | Should -BeFalse
    }

    It 'processes a pipeline of errors' {
        $errors = @(
            [pscustomobject]@{ errorCode = 'InvalidSoftMatch'; attributeName = 'mail'; objectId = 'u1'; anchorsMatch = $false },
            [pscustomobject]@{ errorCode = 'LargeObject'; attributeName = 'thumbnailPhoto'; objectId = 'u2'; anchorsMatch = $false })
        @($errors | Get-SyncErrorRemediation).Count | Should -Be 2
    }
}

Describe 'Get-PrivilegedAccessFinding' {
    BeforeAll {
        function New-Assignment {
            param([string]$Id, [string]$Name, [switch]$Permanent, [switch]$Guest, [switch]$WithMfa,
                  [string]$Role = '62e90394-69f5-4237-9190-012177145e10')
            [pscustomobject]@{
                principalId = $Id; principalDisplayName = $Name; roleDefinitionId = $Role
                roleDisplayName = 'Global Administrator'
                isPermanent = [bool]$Permanent; isGuest = [bool]$Guest; hasMfaMethod = [bool]$WithMfa
            }
        }

        $script:TwoBreakGlass = @(
            (New-Assignment -Id 'bg1' -Name 'break-glass-01' -Permanent -WithMfa),
            (New-Assignment -Id 'bg2' -Name 'break-glass-02' -Permanent -WithMfa))
    }

    It 'grades the expected break-glass accounts as Info, not as violations' {
        $findings = @(Get-PrivilegedAccessFinding -Assignment $script:TwoBreakGlass -BreakGlassId @('bg1', 'bg2'))
        $findings.Count | Should -Be 2
        ($findings | Where-Object Severity -ne 'Info').Count | Should -Be 0
    }

    It 'reports standing privilege held by anyone else' {
        $assignments = $script:TwoBreakGlass + (New-Assignment -Id 'u1' -Name 'Dana' -Permanent -WithMfa)
        $findings = @(Get-PrivilegedAccessFinding -Assignment $assignments -BreakGlassId @('bg1', 'bg2'))
        ($findings | Where-Object { $_.Principal -eq 'Dana' -and $_.Severity -eq 'High' }).Count | Should -Be 1
    }

    It 'reports a privileged account with no strong authentication as Critical' {
        $assignments = $script:TwoBreakGlass + (New-Assignment -Id 'u1' -Name 'Dana' -Permanent)
        $findings = @(Get-PrivilegedAccessFinding -Assignment $assignments -BreakGlassId @('bg1', 'bg2'))
        ($findings | Where-Object { $_.Principal -eq 'Dana' -and $_.Severity -eq 'Critical' }).Count | Should -BeGreaterThan 0
    }

    It 'reports an external guest in a privileged role as Critical' {
        $assignments = $script:TwoBreakGlass + (New-Assignment -Id 'g1' -Name 'Partner' -Guest -WithMfa)
        $findings = @(Get-PrivilegedAccessFinding -Assignment $assignments -BreakGlassId @('bg1', 'bg2'))
        ($findings | Where-Object { $_.Principal -eq 'Partner' -and $_.Severity -eq 'Critical' }).Count | Should -BeGreaterThan 0
    }

    It 'reports a tenant with only one standing Global Administrator' {
        $assignments = @((New-Assignment -Id 'bg1' -Name 'break-glass-01' -Permanent -WithMfa))
        $findings = @(Get-PrivilegedAccessFinding -Assignment $assignments -BreakGlassId @('bg1'))
        ($findings | Where-Object { $_.Principal -eq '(tenant)' }).Detail | Should -Match '1 accounts'
    }

    It 'says nothing about the count when there are exactly two' {
        $findings = @(Get-PrivilegedAccessFinding -Assignment $script:TwoBreakGlass -BreakGlassId @('bg1', 'bg2'))
        ($findings | Where-Object { $_.Principal -eq '(tenant)' }).Count | Should -Be 0
    }
}
