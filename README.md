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

## Two bugs this found in itself

**PowerShell unrolls a `HashSet` on the way out of a function.** `return $set`
emits the set's *members* — nothing at all when it is empty, and a bare string
when it holds one. Every scope comparison silently compared against `$null`, so
a correctly excluded break-glass account was reported as locked out. Fixed with
the comma operator; the same fix applied to arrays over-corrected and made every
empty result look like one item, which flipped the false positive to a false
negative in the other direction.

**A check that could not run reported clean.** The analyzer step refused to load
on an unsupported PowerShell version, both scans errored, and the script printed
`clean` because it only inspected the result count. CI now asserts the analyzer
actually loaded before believing anything about its output. This is the third
time this shape of bug has appeared across this lab series, so it is worth
stating as a rule: **a check that cannot run must fail, never pass quietly.**

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
| PSScriptAnalyzer | clean |
| `terraform validate`, `tflint`, `checkov`, `actionlint` | clean |
| Live proof run | **not yet run** — waiting on a lab tenant |

The logic, the policies and the workflows are complete and verified as far as
they can be without a directory. The end-to-end run against a real tenant is the
remaining step, and this section will say so plainly until it has happened.

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
