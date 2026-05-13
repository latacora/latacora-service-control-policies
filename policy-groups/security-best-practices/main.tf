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
        test     = "ArnLike"
        variable = "aws:PrincipalArn"
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
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
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
        # equivalent to aws-portal:ModifyBilling (deduplicated with aws-portal:ModifyPayments equivalent)
        "billing:PutContractInformation",
        "billing:RedeemCredits",
        "billing:UpdateBillingPreferences",
        # excluding Cost Explorer "create" and "provide feedback" actions to not hinder FinOps
        # "ce:CreateAnomalyMonitor",
        # "ce:CreateAnomalySubscription",
        # "ce:CreateNotificationSubscription",
        # "ce:CreateReport",
        # "ce:ProvideAnomalyFeedback",
        # "ce:StartSavingsPlansPurchaseRecommendationGeneration",
        "ce:DeleteAnomalyMonitor",
        "ce:DeleteAnomalySubscription",
        "ce:DeleteNotificationSubscription",
        "ce:DeleteReport",
        "ce:UpdateAnomalyMonitor",
        "ce:UpdateAnomalySubscription",
        "ce:UpdateCostAllocationTagsStatus",
        "ce:UpdateNotificationSubscription",
        "ce:UpdatePreferences",
        "cur:PutClassicReportPreferences",
        "freetier:PutFreeTierAlertPreference",
        "invoicing:PutInvoiceEmailDeliveryPreferences",
        "tax:BatchPutTaxRegistration",
        "tax:DeleteTaxRegistration",
        "tax:PutTaxInheritance",

        # equivalent to aws-portal:ModifyPaymentMethods
        # excluding "account:GetAccountInformation" since it is commonly legitimately used
        "payments:DeletePaymentInstrument",
        "payments:CreatePaymentInstrument",
        # exclude "payments:MakePayment" to avoid blocking legitimate payments
        # "payments:MakePayment",
        "payments:UpdatePaymentPreferences",

        # equivalent to purchase-orders:ModifyPurchaseOrders
        "purchase-orders:AddPurchaseOrder",
        "purchase-orders:DeletePurchaseOrder",
        "purchase-orders:UpdatePurchaseOrder",
        "purchase-orders:UpdatePurchaseOrderStatus",

        "billing:UpdateIAMAccessPreference",
        "invoicing:CreateInvoiceUnit",
        "invoicing:CreateProcurementPortalPreference",
        "invoicing:DeleteInvoiceUnit",
        "invoicing:DeleteProcurementPortalPreference",
        "invoicing:PutProcurementPortalPreference",
        "invoicing:StartInvoiceCorrection",
        "invoicing:UpdateInvoiceUnit",
        "invoicing:UpdateProcurementPortalPreferenceStatus",
        "payments:AcceptFinancingApplication",
        "payments:CreateFinancingApplication",
        "payments:UpdateFinancingApplication",
        "payments:UpdatePaymentInstrument",
        "tax:BatchDeleteTaxRegistration",
        "tax:CancelTaxDocument",
        "tax:DeleteSupplementalTaxRegistration",
        "tax:PutSupplementalTaxRegistration",
        "tax:PutTaxDocument",
        "tax:PutTaxExemption",
        "tax:PutTaxRegistration",
        "tax:UpdateTaxInterview",
      ]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.deny_account_changes ? [1] : []

    content {
      sid    = "DenyAccountChanges"
      effect = "Deny"
      actions = [
        # equivalent to aws-portal:ModifyAccount, deduplicated with aws-portal:ModifyBilling equivalent above
        "account:CloseAccount",
        "account:DeleteAlternateContact",
        "account:PutAlternateContact",
        "account:PutContactInformation",

        "account:AcceptPrimaryEmailUpdate",
        "account:DisableRegion",
        "account:EnableRegion",
        "account:StartPrimaryEmailUpdate",
      ]
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
