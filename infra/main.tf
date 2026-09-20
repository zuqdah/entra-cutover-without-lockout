# Directory role template IDs are fixed across every tenant, so they are
# constants rather than lookups.
locals {
  role_global_administrator     = "62e90394-69f5-4237-9190-012177145e10"
  role_conditional_access_admin = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
  role_security_administrator   = "194ae4cb-b126-40b2-bd5b-6091b380977d"
  role_exchange_administrator   = "29232cdf-9323-42fd-ade2-1d097af3e4de"
  role_user_administrator       = "fe930be7-5e62-47db-91af-98c3a49a38b1"
  app_azure_management          = "797f4846-ba00-4fd7-ba43-dac1f8f63013"

  privileged_roles = [
    local.role_global_administrator,
    local.role_conditional_access_admin,
    local.role_security_administrator,
    local.role_exchange_administrator,
    local.role_user_administrator,
  ]
}

resource "random_password" "account" {
  for_each = toset(["breakglass01", "breakglass02", "admin", "user"])

  length           = 40
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# The recovery accounts. They are deliberately plain: no MFA method, no managed
# device, nothing that can expire or be revoked by the same outage that made
# them necessary. Everything that protects them is an exclusion, which is why
# the exclusions are what this lab tests.
resource "azuread_user" "break_glass" {
  for_each = toset(["breakglass01", "breakglass02"])

  user_principal_name   = "${var.prefix}-${each.key}@${var.domain}"
  display_name          = "${var.prefix}-${each.key}"
  password              = random_password.account[each.key].result
  force_password_change = false
  job_title             = "Break-glass account - do not use for daily work"
}

resource "azuread_user" "admin" {
  user_principal_name   = "${var.prefix}-admin@${var.domain}"
  display_name          = "${var.prefix}-admin"
  password              = random_password.account["admin"].result
  force_password_change = false
  job_title             = "Cutover administrator"
}

resource "azuread_user" "standard" {
  user_principal_name   = "${var.prefix}-user@${var.domain}"
  display_name          = "${var.prefix}-user"
  password              = random_password.account["user"].result
  force_password_change = false
  job_title             = "Ordinary synced user"
}

# Exclusion by group, not by object ID. Naming the accounts directly in every
# policy means a fourth policy written next year forgets one of them, and the
# forgetting is silent until the day it matters.
resource "azuread_group" "break_glass" {
  display_name     = "${var.prefix}-break-glass"
  description      = "Excluded from every Conditional Access policy that can refuse a sign-in. Membership is the tenant's recovery path."
  security_enabled = true

  members = [for u in azuread_user.break_glass : u.object_id]
}

resource "azuread_directory_role" "global_administrator" {
  template_id = local.role_global_administrator
}

resource "azuread_directory_role_assignment" "break_glass_global_admin" {
  for_each = azuread_user.break_glass

  role_id             = azuread_directory_role.global_administrator.template_id
  principal_object_id = each.value.object_id
}

resource "azuread_directory_role" "user_administrator" {
  template_id = local.role_user_administrator
}

# The working administrator holds a scoped role, not Global Administrator. Two
# standing Global Administrators is the convention; a third because someone
# needed to reset a password is how it stops being one.
resource "azuread_directory_role_assignment" "admin_user_admin" {
  role_id             = azuread_directory_role.user_administrator.template_id
  principal_object_id = azuread_user.admin.object_id
}

# Every policy ships report-only. The proof run evaluates the matrix against
# them in this state, and promotion to enforced is a separate, deliberate step
# that the proof has to pass first.
resource "azuread_conditional_access_policy" "block_legacy_authentication" {
  display_name = "${var.prefix} - Block legacy authentication"
  state        = var.policy_state

  conditions {
    client_app_types = ["exchangeActiveSync", "other"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["block"]
  }
}

resource "azuread_conditional_access_policy" "mfa_for_azure_management" {
  display_name = "${var.prefix} - Require MFA for Azure management"
  state        = var.policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = [local.app_azure_management]
    }

    users {
      included_users  = ["All"]
      excluded_groups = [azuread_group.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}

resource "azuread_conditional_access_policy" "mfa_for_administrators" {
  display_name = "${var.prefix} - Require MFA for administrators"
  state        = var.policy_state

  conditions {
    client_app_types = ["all"]

    applications {
      included_applications = ["All"]
    }

    users {
      included_roles  = local.privileged_roles
      excluded_groups = [azuread_group.break_glass.object_id]
    }
  }

  grant_controls {
    operator          = "OR"
    built_in_controls = ["mfa"]
  }
}
