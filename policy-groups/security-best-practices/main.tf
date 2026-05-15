data "aws_iam_policy_document" "this" {
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

resource "aws_organizations_policy" "this" {
  name        = "security-policy"
  description = "This policy contains the security controls recommended by Latacora for hardening of an organization"
  content     = data.aws_iam_policy_document.this.json
}

resource "aws_organizations_policy_attachment" "this" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.this.id
  target_id = each.value
}
