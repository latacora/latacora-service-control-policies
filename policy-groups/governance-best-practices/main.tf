data "aws_iam_policy_document" "this" {
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
        "quicksight:DescribeAccountSubscription",
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
        "wellarchitected:*",
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
        values   = ["arn:aws:iam::*:role/AWSControlTowerExecution"]
      }
    }
  }
}

resource "aws_organizations_policy" "this" {
  name        = "governance-policy"
  description = "Governance SCPs (e.g. region deny) recommended by Latacora"
  content     = data.aws_iam_policy_document.this.json
}

resource "aws_organizations_policy_attachment" "this" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.this.id
  target_id = each.value
}
