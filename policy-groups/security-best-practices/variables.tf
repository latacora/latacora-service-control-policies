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

variable "deny_cloudtrail_changes" {
  description = "Blocks CloudTrail ability from deleting, stopping and updating cloudtrail"
  default     = true
  type        = bool
}

variable "enabled_regions_policy" {
  description = "enable specific regions?"
  default     = true
  type        = bool
}

variable "enabled_regions" {
  description = "List of regions that are allowed"
  type        = list(string)
}
