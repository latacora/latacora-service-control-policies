variable "target_ids" {
  description = "IDs of the targets (organization roots, OUs, or accounts) to attach the policy to"
  type        = list(string)
}

variable "enabled_regions_policy" {
  description = "Enable the region deny statement"
  default     = true
  type        = bool
}

variable "enabled_regions" {
  description = "List of regions that are allowed"
  type        = list(string)
}
