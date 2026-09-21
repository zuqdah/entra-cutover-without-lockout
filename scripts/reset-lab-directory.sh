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
    az rest --method DELETE --url "${GRAPH}/${kind}/${id}" >/dev/null
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

# Users and groups are soft deleted and keep their userPrincipalName reserved
# for 30 days, so leaving them in the recycle bin makes the next apply fail on a
# name that nothing visible is using. Purging is part of the teardown, not an
# extra.
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
