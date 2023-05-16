locals {
  security_policy       = var.enable_security_policy ? 1 : 0
  infrastructure_policy = var.enable_infrastructure_policy ? 1 : 0
}

module "security_scp" {
  count           = local.security_policy
  source          = "./policy-groups/security-best-practices/"
  target_ou_id    = var.target_ou_id
  enabled_regions = var.enabled_regions
}

module "infrastructure_scp" {
  count        = local.infrastructure_policy
  source       = "./policy-groups/infrastructure-best-practices/"
  target_ou_id = var.target_ou_id
}
