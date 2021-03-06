locals {
  deny_leaving_orgs_statement       = var.deny_leaving_orgs ? [""] : []
  deny_cloudtrail_changes_statement = var.deny_cloudtrail_changes ? [""] : []
  enabled_regions_statement         = var.enabled_regions_policy ? [""] : []
  deny_billing_changes_statement    = var.deny_billing_changes ? [""] : []
  deny_account_changes_statement    = var.deny_account_changes ? [""] : []
}

#
# Combine Policies
#

data "aws_iam_policy_document" "combined_policy_block" {
  #
  # Deny leaving AWS Organizations
  #
  dynamic "statement" {
    for_each = local.deny_leaving_orgs_statement
    content {
      sid       = "DenyLeavingOrgs"
      effect    = "Deny"
      actions   = ["organizations:LeaveOrganization"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.deny_cloudtrail_changes_statement
    content {
      sid    = "DenyCloudtrailChanges"
      effect = "Deny"
      actions = ["cloudtrail:AddTags",
        "cloudtrail:DeleteTrail",
        "cloudtrail:RemoveTags",
        "cloudtrail:StopLogging",
      "cloudtrail:UpdateTrail"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.enabled_regions_statement
    content {
      sid    = "EnabledRegions"
      effect = "Deny"

      # These actions do not operate in a specific region, or only run in
      # a single region, so we don't want to try restricting them by region.
      # List of actions can be found in the following example:
      # https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples_general.html
      not_actions = [
        "a4b:*",
        "access-analyzer:*",
        "acm:*",
        "aws-marketplace-management:*",
        "aws-marketplace:*",
        "aws-portal:*",
        "budgets:*",
        "ce:*",
        "chime:*",
        "cloudfront:*",
        "config:*",
        "cur:*",
        "directconnect:*",
        "ec2:DescribeRegions",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVpnGateways",
        "fms:*",
        "globalaccelerator:*",
        "health:*",
        "iam:*",
        "importexport:*",
        "kms:*",
        "mobileanalytics:*",
        "networkmanager:*",
        "organizations:*",
        "pricing:*",
        "route53:*",
        "route53domains:*",
        "s3:GetAccountPublic*",
        "s3:ListAllMyBuckets",
        "s3:PutAccountPublic*",
        "shield:*",
        "sts:*",
        "support:*",
        "trustedadvisor:*",
        "waf-regional:*",
        "waf:*",
        "wafv2:*",
        "wellarchitected:*"
      ]

      resources = ["*"]

      condition {
        test     = "StringNotEquals"
        variable = "aws:RequestedRegion"
        values   = var.enabled_regions
      }
    }
  }


  dynamic "statement" {
    for_each = local.deny_billing_changes_statement
    content {
      sid    = "DenyBillingChanges"
      effect = "Deny"
      actions = ["aws-portal:ModifyBilling",
      "aws-portal:ModifyPaymentMethods"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.deny_account_changes_statement
    content {
      sid       = "DenyAccountChanges"
      effect    = "Deny"
      actions   = ["aws-portal:ModifyAccount"]
      resources = ["*"]
    }
  }

}

resource "aws_organizations_policy" "security_hardened_policy" {
  name        = "security-policy"
  description = "This policy contains the security controls recommended by Latacora for hardening of an organization"
  content     = data.aws_iam_policy_document.combined_policy_block.json
}

resource "aws_organizations_policy_attachment" "policy_attachment" {
  policy_id = aws_organizations_policy.security_hardened_policy.id
  target_id = var.target_ou_id
}
