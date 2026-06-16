module "security_scp" {
  count      = var.enable_security_policy ? 1 : 0
  source     = "./policy-groups/security-best-practices/"
  target_ids = var.security_policy_target_ids
}

module "infrastructure_scp" {
  count      = var.enable_infrastructure_policy ? 1 : 0
  source     = "./policy-groups/infrastructure-best-practices/"
  target_ids = var.infrastructure_policy_target_ids
}

module "governance_scp" {
  count           = var.enable_governance_policy ? 1 : 0
  source          = "./policy-groups/governance-best-practices/"
  target_ids      = var.governance_policy_target_ids
  enabled_regions = var.enabled_regions
}
