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
        test     = "StringLike"
        variable = "awsPrincipalArn"
        values   = ["arn:aws:iam::*:root"]
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
      # Also merge in changes from Control Tower Region Deny control: https://docs.aws.amazon.com/controltower/latest/userguide/primary-region-deny-policy.html
      not_actions = [
        "a4b:*",
        "access-analyzer:*",
        "account:*",
        "acm:*",
        "activate:*",
        "artifact:*",
        "aws-marketplace-management:*",
        "aws-marketplace:*",
        "aws-portal:*",
        "billing:*",
        "billingconductor:*",
        "budgets:*",
        "ce:*",
        "chatbot:*",
        "chime:*",
        "cloudfront:*",
        "cloudtrail:LookupEvents",
        "compute-optimizer:*",
        "config:*",
        "consoleapp:*",
        "consolidatedbilling:*",
        "cur:*",
        "datapipeline:GetAccountLimits",
        "devicefarm:*",
        "directconnect:*",
        "discovery-marketplace:*",
        "ec2:DescribeRegions",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeVpnGateways",
        "ecr-public:*",
        "fms:*",
        "freetier:*",
        "globalaccelerator:*",
        "health:*",
        "iam:*",
        "importexport:*",
        "invoicing:*",
        "iq:*",
        "kms:*",
        "license-manager:ListReceivedLicenses",
        "lightsail:Get*",
        "mobileanalytics:*",
        "networkmanager:*",
        "notifications-contacts:*",
        "notifications:*",
        "organizations:*",
        "payments:*",
        "pricing:*",
        "resource-explorer-2:*",
        "route53-recovery-cluster:*",
        "route53-recovery-control-config:*",
        "route53-recovery-readiness:*",
        "route53:*",
        "route53domains:*",
        "s3:CreateMultiRegionAccessPoint",
        "s3:DeleteMultiRegionAccessPoint",
        "s3:DescribeMultiRegionAccessPointOperation",
        "s3:GetAccountPublicAccessBlock",
        "s3:GetBucketLocation",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetMultiRegionAccessPoint",
        "s3:GetMultiRegionAccessPointPolicy",
        "s3:GetMultiRegionAccessPointPolicyStatus",
        "s3:GetStorageLensConfiguration",
        "s3:GetStorageLensDashboard",
        "s3:ListAllMyBuckets",
        "s3:ListMultiRegionAccessPoints",
        "s3:ListStorageLensConfigurations",
        "s3:PutAccountPublicAccessBlock",
        "s3:PutMultiRegionAccessPointPolicy",
        "savingsplans:*",
        "shield:*",
        "sso:*",
        "sts:*",
        "support:*",
        "supportapp:*",
        "supportplans:*",
        "sustainability:*",
        "tag:GetResources",
        "tax:*",
        "trustedadvisor:*",
        "vendor-insights:ListEntitledSecurityProfiles",
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
      # Allow Control Tower to bypass this SCP
      condition {
        test     = "ArnNotLike"
        variable = "aws:PrincipalARN"
        values = [
          "arn:aws:iam::*:role/AWSControlTowerExecution"
        ]
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
