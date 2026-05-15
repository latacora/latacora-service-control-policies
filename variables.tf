variable "enable_security_policy" {
  description = "Enables the Security Best Practices SCP"
  type        = bool
  default     = true
}

variable "enable_infrastructure_policy" {
  description = "Enables the Infrastructure Best Practices SCP"
  type        = bool
  default     = true
}

variable "enable_governance_policy" {
  description = "Enables the Governance Best Practices SCP (e.g. region deny)"
  type        = bool
  default     = true
}

variable "security_policy_target_ids" {
  description = "Targets (organization roots, OUs, or accounts) to attach the security SCP to"
  type        = list(string)
  default     = []
}

variable "infrastructure_policy_target_ids" {
  description = "Targets (organization roots, OUs, or accounts) to attach the infrastructure SCP to"
  type        = list(string)
  default     = []
}

variable "governance_policy_target_ids" {
  description = "Targets (organization roots, OUs, or accounts) to attach the governance SCP to"
  type        = list(string)
  default     = []
}

variable "enabled_regions" {
  description = "List of regions that are allowed (used by the governance SCP). Defaults to us-east-1 so callers don't accidentally lock themselves out of global-service endpoints."
  type        = list(string)
  default     = ["us-east-1"]
}
