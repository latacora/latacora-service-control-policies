variable "target_ou_id" {
  description = "id of the organization unit to attach the policy to"
  type        = string
}

# Policy Statement Switches
variable "deny_leaving_orgs" {
  description = "DenyLeavingOrgs in the OU policy."
  default     = true
  type        = bool
}

variable "restrict_member_account_root_users" {
  description = "Deny actions to member account root users"
  default     = true
  type        = bool
}

variable "deny_cloudtrail_changes" {
  description = "Denies access to deleting, updating, or stoppng Cloudtrail"
  default     = true
  type        = bool
}

variable "deny_billing_changes" {
  description = "Denies access to make billing changes"
  default     = true
  type        = bool
}

variable "deny_account_changes" {
  description = "Denies access to make account changes"
  default     = true
  type        = bool
}

variable "enabled_regions_policy" {
  description = "Enable specific regions"
  default     = true
  type        = bool
}

variable "enabled_regions" {
  description = "List of regions that are allowed"
  type        = list(string)
}
