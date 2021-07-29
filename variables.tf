variable "target_ou_id" {
  description = "id of the organization unit to attach the policy to"
  type        = string
}

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

variable "enabled_regions" {
  description = "List of regions that are allowed"
  type        = list(string)
}
