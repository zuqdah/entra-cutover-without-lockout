variable "tenant_id" {
  description = "The lab directory this runs against. Never the directory that holds production mail: enabling directory synchronisation is a tenant-wide change that takes up to 72 hours to reverse and cannot be cancelled once started."
  type        = string

  validation {
    condition     = can(regex("^[0-9a-fA-F-]{36}$", var.tenant_id))
    error_message = "tenant_id must be a GUID."
  }
}

variable "domain" {
  description = "A verified domain in the lab tenant, used as the UPN suffix for the lab accounts."
  type        = string
}

variable "prefix" {
  description = "Name prefix for every object this lab creates, so a stray object is obvious in the directory."
  type        = string
  default     = "cutover"
}

variable "policy_state" {
  description = "Conditional Access policies deploy report-only. Enforcing them is a separate decision that the proof run has to earn."
  type        = string
  default     = "enabledForReportingButNotEnforced"

  validation {
    condition     = contains(["disabled", "enabledForReportingButNotEnforced", "enabled"], var.policy_state)
    error_message = "policy_state must be disabled, enabledForReportingButNotEnforced or enabled."
  }
}
