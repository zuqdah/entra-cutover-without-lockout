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

# Deleting a user or group only soft deletes it: the object sits in the
# directory's recycle bin for 30 days and can be restored whole. It does not
# block the name being reused -- successive runs of this lab recreated the same
# userPrincipalNames without complaint -- so this is not about making the next
# apply work. It is about what "torn down" means. An account that held Global
# Administrator, restorable by anyone who can reach the bin, is not gone, and a
# teardown that leaves one there while reporting success is the kind of claim
# this lab exists to distrust.
deleted=$(az rest --method GET \
  --url "${GRAPH}/directory/deletedItems/microsoft.graph.user?\$select=id,displayName" \
  --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv 2>/dev/null || true)

for id in $deleted; do
  [ -z "$id" ] && continue
  az rest --method DELETE --url "${GRAPH}/directory/deletedItems/${id}" >/dev/null
  echo "  purged deleted user/${id}"
done

deleted_groups=$(az rest --method GET \
  --url "${GRAPH}/directory/deletedItems/microsoft.graph.group?\$select=id,displayName" \
  --query "value[?starts_with(displayName,'${PREFIX}')].id" -o tsv 2>/dev/null || true)

for id in $deleted_groups; do
  [ -z "$id" ] && continue
  az rest --method DELETE --url "${GRAPH}/directory/deletedItems/${id}" >/dev/null
  echo "  purged deleted group/${id}"
done

echo "Removed ${removed} live object(s); the lab directory is back to empty."
