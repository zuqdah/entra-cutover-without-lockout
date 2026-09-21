#!/usr/bin/env bash
#
# Returns the lab directory to empty. Used by both the proof run, which needs a
# known-empty starting point, and the nightly teardown.
#
# This lab keeps no remote state. The directory it runs against is disposable
# and emptied nightly, which makes the directory itself the source of truth:
# deleting by name prefix finds every object, including ones a partially failed
# apply orphaned and ones somebody made by hand in the portal. A state-based
# destroy would miss both by definition, and in a fresh runner with no state it
# would find nothing at all and report success over a full directory.
#
# The order below is the part that matters. Graph refuses to delete a user
# holding a privileged directory role when the caller's authority is only
# User.ReadWrite.All -- the break-glass accounts hold Global Administrator, so a
# straight delete returns Authorization_RequestDenied. The usual answer is to
# give the automation Global Administrator. Instead this strips the role
# assignment first and then deletes an ordinary user, which is the same outcome
# without an identity that holds standing Global Administrator in order to
# perform a cleanup.

set -euo pipefail

PREFIX="${1:-cutover}"
GRAPH="https://graph.microsoft.com/v1.0"
removed=0

# Dropping a role assignment is accepted immediately and takes a few seconds to
# be reflected in the check that guards deleting the account. Deleting straight
# afterwards gets Authorization_RequestDenied on an account that is, by then,
# not actually privileged -- so the refusal is retried rather than treated as
# final. Every other status is final on the first attempt, because retrying a
# real permission problem just reports it more slowly.
delete_with_retry() {
  local url="$1"
  local label="$2"
  local attempt=0
  local output

  while : ; do
    attempt=$((attempt + 1))
    if output=$(az rest --method DELETE --url "$url" 2>&1); then
      return 0
    fi

    if ! grep -q 'Authorization_RequestDenied' <<<"$output"; then
      echo "  failed to remove ${label}: ${output}" >&2
      return 1
    fi

    if [ "$attempt" -ge 6 ]; then
      echo "  gave up on ${label} after ${attempt} attempts; still reported as privileged" >&2
      return 1
    fi

    echo "  ${label} still reads as privileged, waiting for the role removal to land (attempt ${attempt})"
    sleep 10
  done
}

echo "Resetting objects named '${PREFIX}*'."

# Principals first, so their role assignments can be found before the objects
# they belong to are gone.
principals=$(az rest --method GET \
  --url "${GRAPH}/users?\$select=id,displayName" \
  --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv)

for id in $principals; do
  [ -z "$id" ] && continue
  assignments=$(az rest --method GET \
    --url "${GRAPH}/roleManagement/directory/roleAssignments?\$filter=principalId%20eq%20'${id}'" \
    --query "value[].id" -o tsv 2>/dev/null || true)

  for assignment in $assignments; do
    [ -z "$assignment" ] && continue
    az rest --method DELETE --url "${GRAPH}/roleManagement/directory/roleAssignments/${assignment}" >/dev/null
    echo "  dropped role assignment ${assignment} from ${id}"
  done
done

for kind in users groups; do
  ids=$(az rest --method GET \
    --url "${GRAPH}/${kind}?\$select=id,displayName" \
    --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv)

  for id in $ids; do
    [ -z "$id" ] && continue
    delete_with_retry "${GRAPH}/${kind}/${id}" "${kind}/${id}"
    echo "  removed ${kind}/${id}"
    removed=$((removed + 1))
  done
done

# The URL is single-quoted on purpose: $select is an OData parameter and has to
# reach Graph literally rather than being expanded by the shell.
policies=$(az rest --method GET \
  --url "${GRAPH}/identity/conditionalAccess/policies?\$select=id,displayName" \
  --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv)

for id in $policies; do
  [ -z "$id" ] && continue
  az rest --method DELETE --url "${GRAPH}/identity/conditionalAccess/policies/${id}" >/dev/null
  echo "  removed policy/${id}"
  removed=$((removed + 1))
done

# A DELETE being accepted is not the same as the name being free, and the
# reason is specific. Deleting a user soft deletes it, and on the way into the
# recycle bin Entra rewrites its userPrincipalName to prepend the object ID:
#
#   cutover-admin@lab      ->  72f13840...cutover-admin@lab
#
# That rename is what releases the original name, and it lands a beat after the
# DELETE returns 200. An apply that starts immediately therefore fails with
# "Another object with the same value for property userPrincipalName already
# exists" about an account that no longer appears in any list -- which is a
# genuinely baffling error to read.
#
# So this waits on the rename rather than on its own return codes. The count
# that matters is objects still holding an un-rewritten name: an entry sitting
# in the bin under its rewritten name blocks nothing.
echo "Waiting for the deleted names to be released."

for attempt in $(seq 1 30); do
  live_users=$(az rest --method GET \
    --url "${GRAPH}/users?\$select=id,displayName" \
    --query "length(value[?starts_with(displayName,'${PREFIX}')])" -o tsv)
  live_groups=$(az rest --method GET \
    --url "${GRAPH}/groups?\$select=id,displayName" \
    --query "length(value[?starts_with(displayName,'${PREFIX}')])" -o tsv)

  # Bin entries whose UPN still begins with the prefix have not been rewritten
  # yet and are still holding the name.
  unreleased=$(az rest --method GET \
    --url "${GRAPH}/directory/deletedItems/microsoft.graph.user?\$select=id,userPrincipalName" \
    --query "length(value[?starts_with(userPrincipalName,'${PREFIX}')])" -o tsv 2>/dev/null || echo 0)

  total=$((live_users + live_groups + unreleased))
  if [ "$total" -eq 0 ]; then
    echo "  names released after ${attempt} check(s)."
    break
  fi

  if [ "$attempt" -eq 30 ]; then
    echo "Objects named '${PREFIX}*' still hold their names after five minutes." >&2
    echo "Applying now would fail on a name that is still claimed, so this stops here." >&2
    exit 1
  fi

  echo "  still holding a name: ${live_users} user(s), ${live_groups} group(s), ${unreleased} awaiting rename (attempt ${attempt})"
  sleep 10
done

# Purging happens last, once the names are free, because the bin cannot be
# queried for an object that has only just been deleted -- an earlier version of
# this script purged before the deletions had landed there and so purged
# nothing, silently.
#
# This is about what "torn down" means rather than about making the next apply
# work. An account that held Global Administrator, restorable in full by anyone
# who can reach the recycle bin, is not gone; a teardown that leaves one there
# and reports success is the kind of claim this lab exists to distrust. It is
# best effort, and says so out loud when it cannot finish, because an
# unpurgeable leftover should not block a proof run that is otherwise fine.
purged=0
for type in user group; do
  ids=$(az rest --method GET \
    --url "${GRAPH}/directory/deletedItems/microsoft.graph.${type}?\$select=id,displayName" \
    --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv 2>/dev/null || true)

  for id in $ids; do
    [ -z "$id" ] && continue
    if az rest --method DELETE --url "${GRAPH}/directory/deletedItems/${id}" >/dev/null 2>&1; then
      echo "  purged deleted ${type}/${id}"
      purged=$((purged + 1))
    else
      echo "  WARNING: could not purge deleted ${type}/${id}; it stays restorable until Entra expires it" >&2
    fi
  done
done

echo "Removed ${removed} live object(s), purged ${purged} from the recycle bin."
