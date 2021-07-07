variable "target_ou_id" {
  description = "id of the organization unit to attach the policy to"
  type        = string
}

# Policy Statement Switches

variable "deny_leaving_orgs" {
  description = "DenyLeavingOrgs in the OU policy."
  default     = false
  type        = bool
}

variable "deny_cloudtrail_changes" {
  description = "Blocks CloudTrail ability from deleting, stopping and updating cloudtrail"
  default     = true
  type        = bool
}

variable "require_imdsv2" {
  description = "This will only allow ec2 instances to be created with IMDSv2 enabled"
  default     = false
  type        = bool
}


variable "deny_imds_change" {
  description = "Disallows changes to IMDS on instances"
  default     = false
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
