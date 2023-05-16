#
# Combine Policies
#

data "aws_iam_policy_document" "combined_policy_block" {
  #
  # Deny leaving AWS Organizations
  #
  dynamic "statement" {
    for_each = var.deny_leaving_orgs ? [1] : []

    content {
      sid       = "DenyLeavingOrgs"
      effect    = "Deny"
      actions   = ["organizations:LeaveOrganization"]
      resources = ["*"]
    }
  }

  # https://docs.aws.amazon.com/organizations/latest/userguide/best-practices_member-acct.html#best-practices_mbr-acct_scp
  dynamic "statement" {
    for_each = var.restrict_member_account_root_users ? [1] : []

    content {
      sid       = "RestrictMemberAccountRootUsers"
      effect    = "Deny"
      actions   = ["*"]
      resources = ["*"]

      condition {
        test = "StringLike"
        variable = "awsPrincipalArn"
        values = ["arn:aws:iam::*:root"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_cloudtrail_changes ? [1] : []

    content {
      sid    = "DenyCloudtrailChanges"
      effect = "Deny"
      actions = [
        "cloudtrail:AddTags",
        "cloudtrail:DeleteTrail",
        "cloudtrail:RemoveTags",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.enabled_regions_policy ? [1] : []

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
        "wellarchitected:*",
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
    for_each = var.deny_billing_changes ? [1] : []

    content {
      sid    = "DenyBillingChanges"
      effect = "Deny"
      actions = [
        "aws-portal:ModifyBilling",
        "aws-portal:ModifyPaymentMethods",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.deny_account_changes ? [1] : []

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
