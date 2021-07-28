locals {
  deny_leaving_orgs_statement       = var.deny_leaving_orgs ? [""] : []
  deny_cloudtrail_changes_statement = var.deny_cloudtrail_changes ? [""] : []
  require_imdsv2_statement          = var.require_imdsv2 ? [""] : []
  deny_imds_change_statement        = var.deny_imds_change ? [""] : []
  enabled_regions_statement         = var.enabled_regions_policy ? [""] : []
  require_ebs_encryption_statement  = var.require_ebs_encryption ? [""] : []
  require_s3_encryption_statement   = var.require_s3_encryption ? [""] : []
  require_s3_bucket_https_statement = var.require_s3_bucket_https ? [""] : []
  deny_s3_public_access_statement   = var.deny_s3_public_access ? [""] : []
  require_rds_encryption_statement  = var.require_rds_encryption ? [""] : []
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
    for_each = local.require_imdsv2_statement
    content {
      sid       = "RequireIMDSv2"
      effect    = "Deny"
      actions   = "ec2:RunInstances"
      resources = ["arn:aws:ec2:*:*:instance/*"]
      condition {
        test     = "StringLike"
        variable = "ec2:MetadataHttpsTokens"
        values   = ["required"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.deny_imds_change_statement
    content {
      sid       = "DenyIMDSChanges"
      effect    = "Deny"
      actions   = "ec2:ModifyInstanceMetadataOptions"
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
    for_each = local.require_ebs_encryption_statement
    content {
      sid    = "RequireEBSEncryption"
      effect = "Deny"
      actions = ["ec2:CreateVolume",
        "ec2:CreateSnapshot",
      "ec2:CreateSnapshots"]
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "ec2:Encrypted"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = local.require_s3_encryption_statement
    content {
      sid    = "RequireS3DefaultEncryption"
      effect = "Deny"
      actions = ["s3:CreateBucket",
      "s3:PutBucketEncryption"]
      resources = ["*"]
      condition {
        test     = "ForAllValues:StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["AES256", "aws:kms"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.require_s3_bucket_https_statement
    content {
      sid       = "RequireS3BucketHTTPS"
      effect    = "Deny"
      actions   = "s3:PutBucketPolicy"
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = local.deny_s3_public_access_statement
    content {
      sid    = "DenyPublicAccesstoS3Buckets"
      effect = "Deny"
      actions = ["s3:PutPublicAccessBlock",
      "s3:GetPublicAccessBlock"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.require_rds_encryption_statement
    content {
      sid       = "RequireRDSEncryption"
      effect    = "Deny"
      actions   = "rds:CreateDBInstance"
      resources = ["*"]
      condition {
        test     = "Bool"
        variable = "rds:StorageEncrypted"
        values   = [false]
      }
    }
  }
}

resource "aws_organizations_policy" "security_hardened_policy" {
  name        = "organization_security_policy"
  description = "This policy contains the security controls recommended by Latacora for hardening of an organization"
  content     = data.aws_iam_policy_document.combined_policy_block.json

}

resource "aws_organizations_policy_attachment" "policy_attachment" {
  policy_id = aws_organizations_policy.security_hardened_policy.id
  target_id = var.target_ou_id
}
