output "break_glass_group_id" {
  description = "The group whose membership is the tenant's recovery path."
  value       = azuread_group.break_glass.object_id
}

output "identities" {
  description = "Object IDs for the accounts the scenario matrix names."
  value = {
    breakGlass   = values(azuread_user.break_glass)[0].object_id
    admin        = azuread_user.admin.object_id
    standardUser = azuread_user.standard.object_id
  }
}

output "policy_ids" {
  description = "The Conditional Access policies this lab owns, so the proof reports on these and not on anything else in the tenant."
  value = [
    azuread_conditional_access_policy.block_legacy_authentication.id,
    azuread_conditional_access_policy.mfa_for_azure_management.id,
    azuread_conditional_access_policy.mfa_for_administrators.id,
  ]
}
