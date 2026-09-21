# entra-cutover-without-lockout

Conditional Access defined in Terraform, deployed report-only, and then evaluated
against a declared matrix of sign-in scenarios before anything is enforced — so a
policy that would shut the administrators out of their own tenant is found while
it is still free to fix.

## The problem

Conditional Access is the only control in Entra ID that can lock you out of the
thing you need in order to undo it. Every other mistake is recoverable by signing
in and correcting it. This one takes away the signing in.

The usual advice is to exclude a break-glass account from every blocking policy.
That advice is correct and almost never verified, because verifying it by hand
means reasoning about the interaction of every policy, every group, every
directory role and every grant control at once — and then doing it again after
the next policy is added.

This lab does that reasoning in code, against the directory's own evaluation
engine rather than against an assumption about it.

## What it does

Three Conditional Access policies deploy in `enabledForReportingButNotEnforced`
state, so nothing is enforced while the lab runs. Then two independent checks
have to pass before promotion is offered.

**The scenario matrix.** [`scenario-matrix.json`](scenario-matrix.json) states
what should happen for seven sign-ins and why each one is stated that way. The
proof run asks Microsoft Graph's
[What If evaluation API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-evaluate?view=graph-rest-1.0)
what would actually happen and fails on any disagreement.

**The lockout analysis.** The policies are read back out of the directory — not
out of the Terraform plan, so anything added by hand in the portal is included —
and checked against the break-glass accounts. This is not implied by the matrix
passing: a matrix can be entirely satisfied by policies that also happen to
refuse every account capable of rolling them back.

Only if both pass does the `promote` input do anything. Enforcement is not a
checkbox someone ticks; it is something the evaluation has to earn.

## The part that is easy to get wrong

The What If API answers a narrower question than its name suggests. It reports,
per policy, **whether that policy applies** — not what the sign-in outcome is.
Two consequences, both of which produce a confidently wrong answer:

- **A report-only policy returns `policyApplies: true`.** It applies, in the
  sense the API means, and enforces nothing. Folding those into the verdict
  predicts `Blocked` for a sign-in that in reality succeeds.
- **`analysisReasons: notEnoughInformation` means the service declined to
  judge**, usually because the request omitted a condition the policy tests.
  That is not the same as "does not apply". Counting it as a pass is an
  evaluation reporting success about something it never evaluated.

So [`Get-EffectiveVerdict`](module/HybridIdentity/HybridIdentity.psm1) separates
enforcing policies from report-only ones and takes a
`-TreatReportOnlyAsEnforced` switch, because "what happens today" and "what would
happen on promotion" are different questions and the second is the one worth
asking while there is still time to change the answer. Anything the service could
not decide surfaces as `Inconclusive` and **fails** the comparison.

## Avoiding the findings nobody reads

A lockout checker that flags everything is the same as no checker. All four of
these have to hold at once before a policy is called a lockout:

| Test | Why dropping it ruins the report |
|---|---|
| The policy is on | A disabled policy cannot refuse anything |
| It applies to the account after exclusions | Exclusion can come from a **group** or a **directory role**, not just `excludeUsers`. Comparing object IDs alone flags every correctly configured tenant |
| It covers a surface needed to undo it | A policy blocking one SaaS app is not a lockout however blunt its grant controls are |
| The account cannot satisfy its grant controls | "Require MFA" locks out a break-glass account precisely because that account deliberately has no MFA method |

Report-only policies are graded `High` rather than `Critical`. They cannot lock
anyone out today, and calling them Critical teaches the reader that Critical
means nothing.

The same restraint runs through the rest of the module. The privileged access
review expects exactly two accounts to hold standing Global Administrator and
grades them `Info` — reporting the break-glass accounts as violations is how a
report gets skimmed. `Get-SyncErrorRemediation` will auto-fix a duplicate
address between two records of the same person and will **never** auto-fix an
`InvalidSoftMatch`, which is the same error text about two records that may be
different people; resolving it wrongly welds one person's mailbox onto another's
account.

## What the runs actually taught

Before a directory was involved, two bugs came out of the unit tests:

**PowerShell unrolls a `HashSet` on the way out of a function.** `return $set`
emits the set's *members* — nothing at all when it is empty, and a bare string
when it holds one. Every scope comparison silently compared against `$null`, so
a correctly excluded break-glass account was reported as locked out. Fixed with
the comma operator; the same fix applied to arrays over-corrected and made every
empty result look like one item, which flipped the false positive to a false
negative in the other direction.

**A check that could not run reported clean.** The analyzer refused to load on
an unsupported PowerShell version, both scans errored, and the script printed
`clean` because it only inspected the result count. CI now asserts the analyzer
loaded before believing anything about its output.

Then the live runs found things no fixture would have:

**Naming an application in a policy needs a permission that using `All` does
not.** Two of the three policies created and the third returned 403:
`Application.Read.All scope is required to add/edit application condition`. A
policy scoped to `["All"]` needs no application lookup; one that names
`797f4846-…` needs Entra to resolve it.

**`User.ReadWrite.All` cannot delete a user who holds a privileged directory
role.** The break-glass accounts hold Global Administrator, so teardown failed
with `Authorization_RequestDenied`. The common answer is to give the automation
Global Administrator. This drops the role assignment first and then deletes an
ordinary user — the same end state, without an identity holding standing Global
Administrator in order to run a cleanup.

**Soft deletion renames the account, and the rename is what frees the name.**
A deleted user goes to the recycle bin with its `userPrincipalName` rewritten to
prepend its object ID:

```
cutover-admin@lab  ->  72f13840ab56...cutover-admin@lab
```

That rename lands a beat after the `DELETE` returns `200`, so an apply starting
immediately failed with *"Another object with the same value for property
userPrincipalName already exists"* about an account that appeared in no list.
Two wrong guesses preceded the right one — first that the bin reserves the name
(it does not, it holds the rewritten one), then that purging was needed to free
it (purging is asynchronous and made the race worse). The reset now waits on the
rename itself.

**The teardown's read-back earned its keep on the first real teardown.** The
deletion step reported success and a Conditional Access policy was still listed
afterwards. It had gone a moment later, so it was propagation rather than a
failed delete — but a teardown that had trusted its own return codes would have
reported a clean directory over a live policy. It now polls for three minutes
and then fails, rather than retrying forever or treating a timeout as good
enough.

**The What If endpoint returns an occasional 500.** One run died on the second
of seven calls; the same request replayed immediately succeeded, and seven
sequential replays all succeeded. Transient statuses are retried and nothing
else is, because retrying a 403 takes four times as long to report the same
deterministic failure and hides which kind it was.

The thread running through most of these: **an accepted call is not a completed
one, and a check that cannot run must fail rather than pass quietly.**

## Running it

Requires a **separate Entra tenant**, not one holding production mail. Two
reasons, and the second is the serious one:

- Conditional Access requires an Entra ID P1 licence. A new tenant can activate
  a [P2 trial](https://learn.microsoft.com/en-us/entra/fundamentals/get-started-premium)
  — 31 days, 100 licences, no cost.
- Directory synchronisation is a tenant-wide setting, and
  [turning it off takes up to 72 hours and cannot be cancelled once started](https://learn.microsoft.com/en-us/microsoft-365/enterprise/turn-off-directory-synchronization?view=o365-worldwide).

```bash
terraform -chdir=infra init
terraform -chdir=infra apply -var tenant_id=<lab tenant> -var domain=<verified domain>
```

Then run **Prove** from the Actions tab. `promote: true` enforces the policies,
and only after the proof has passed on that exact configuration.

A nightly **Destroy** removes every object and then checks the directory
directly, because Terraform reporting success is not the same as the tenant
being clean.

## Status

| | |
|---|---|
| Unit tests | 61, green, no directory required |
| PSScriptAnalyzer, `terraform validate`, `tflint`, `checkov`, `actionlint`, `shellcheck` | clean |
| Live proof run | **passed** against a real tenant, 7/7 scenarios, 0 lockouts |
| Teardown | **verified** against the directory afterwards, 0 objects left |
| Promotion to enforced | **not exercised** — see below |

The proof run's own output:

```
ok   break-glass reaches Azure management                          Granted
ok   break-glass reaches Azure management from an unusual country  Granted
ok   administrator reaches Azure management                        MfaRequired
ok   administrator on a legacy client                              Blocked
ok   standard user reaches Office 365                              Granted
ok   standard user on a legacy client                              Blocked
ok   standard user reaches Azure management                        MfaRequired
ok   every break-glass account can still reach a recovery surface
```

**Promotion has deliberately not been run.** The `promote` path is the one step
whose failure mode is a locked tenant, and the accounts that would recover it
hold passwords generated into ephemeral Terraform state — so in this lab there
is no usable break-glass, which is precisely the situation the code refuses to
declare safe. Saying that plainly is better than claiming an untested path
works.

## Permissions the automation holds

Application permissions on Microsoft Graph, granted to a single app registration
that authenticates by federated credential and holds no secret:

| Permission | Why |
|---|---|
| `Policy.ReadWrite.ConditionalAccess` | Create and read the policies |
| `Policy.Read.All` | Read tenant policy state |
| `Application.Read.All` | Resolve application IDs named in policy conditions |
| `User.ReadWrite.All`, `Group.ReadWrite.All` | Create and remove the lab identities |
| `RoleManagement.ReadWrite.Directory` | Assign and remove directory roles |
| `UserAuthenticationMethod.Read.All` | Read whether break-glass has a second factor registered |
| `User.DeleteRestore.All` | Purge the recycle bin so teardown is complete |

`RoleManagement.ReadWrite.Directory` is the sharp one: it can assign any
directory role, Global Administrator included, which makes it a privilege
escalation path in its own right. It is appropriate for a disposable lab tenant
and is not something to hand out in a directory that matters.

## On state

There is no remote backend. The directory this runs against is disposable and
emptied nightly, so the directory is the source of truth: a run starts by
returning it to empty, and teardown deletes by name prefix rather than from
state. That also catches objects a partially failed apply orphaned and objects
created by hand in the portal, both of which a state-based destroy misses by
definition — and in a fresh runner with no state, a `terraform destroy` finds
nothing to do and reports success over a full directory.

The tradeoff is real and worth naming: this is not how a durable environment
should be managed, and for anything that outlives a night the state belongs in a
remote backend with locking.

## What this does not do

It does not evaluate named locations, authentication contexts, or risk-based
conditions — the matrix covers client app type, device platform and country. It
does not judge a specific authentication strength: where a policy requires one,
the account facts have to state whether they satisfy it, and if they do not say,
the requirement is treated as unsatisfiable and reported as unevaluated rather
than assumed away.

It also does not synchronise a real Active Directory forest. The sync-error
triage and tenant-merge collision analysis in the module operate on directory
exports and are covered by unit tests, not by a live Entra Connect installation.
