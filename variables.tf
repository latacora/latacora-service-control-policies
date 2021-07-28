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
  default     = false
  type        = bool
}

variable "require_imdsv2" {
  description = "This will only allow ec2 instances to be created with IMDSv2 enabled"
  default     = true
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

variable "require_ebs_encryption" {
  description = "Requires EBS volumes and snapshots to be encrypted"
  default     = true
  type        = bool
}

variable "require_s3_encryption" {
  description = "Requires s3 default encryption"
  default     = true
  type        = bool
}

variable "require_s3_bucket_https" {
  description = "Requires https on s3 buckets"
  default     = true
  type        = bool
}

variable "deny_s3_public_access" {
  description = "Denies public access to s3 buckets"
  default     = false
  type        = bool
}

variable "require_rds_encryption" {
  description = "Requires RDS encryption"
  default     = true
  type        = bool
}
