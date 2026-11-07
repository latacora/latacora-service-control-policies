data "aws_iam_policy_document" "infrastructure" {
  dynamic "statement" {
    for_each = var.require_imdsv2 ? [1] : []

    content {
      sid       = "RequireIMDSv2"
      effect    = "Deny"
      actions   = ["ec2:RunInstances"]
      resources = ["arn:aws:ec2:*:*:instance/*"]

      condition {
        test     = "StringNotEquals"
        variable = "ec2:MetadataHttpTokens"
        values   = ["required"]
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_imds_change ? [1] : []

    content {
      sid       = "DenyIMDSChanges"
      effect    = "Deny"
      actions   = ["ec2:ModifyInstanceMetadataOptions"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.require_ebs_encryption ? [1] : []

    content {
      sid    = "RequireEBSEncryption"
      effect = "Deny"
      # RunInstances creates root and block-device-mapping volumes without
      # calling CreateVolume, so both actions are needed.
      actions   = ["ec2:CreateVolume", "ec2:RunInstances"]
      resources = ["arn:aws:ec2:*:*:volume/*"]

      condition {
        test     = "Bool"
        variable = "ec2:Encrypted"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_ebs_encryption_by_default_changes ? [1] : []

    content {
      sid       = "DenyEbsEncryptionByDefaultChanges"
      effect    = "Deny"
      actions   = ["ec2:DisableEbsEncryptionByDefault"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.require_s3_bucket_https ? [1] : []

    content {
      sid       = "RequireS3BucketHTTPS"
      effect    = "Deny"
      actions   = ["s3:*"]
      resources = ["*"]

      condition {
        test     = "Bool"
        variable = "aws:SecureTransport"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = var.deny_s3_public_access ? [1] : []

    content {
      sid       = "DenyPublicAccesstoS3Buckets"
      effect    = "Deny"
      actions   = ["s3:PutAccountPublicAccessBlock"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = var.require_rds_encryption ? [1] : []

    content {
      sid    = "DenyUnencryptedRDS"
      effect = "Deny"
      # The following restore APIs are intentionally omitted:
      #   - rds:RestoreDBInstanceFromDBSnapshot
      #   - rds:RestoreDBInstanceToPointInTime
      #   - rds:RestoreDBClusterFromSnapshot
      #   - rds:RestoreDBClusterToPointInTime
      # These APIs do not expose StorageEncrypted as a request parameter, so
      # rds:StorageEncrypted is not available for this condition. Restored DB
      # encryption must be enforced by keeping source snapshots, backups, and
      # DB resources encrypted.
      actions = [
        "rds:CreateDBInstance",
        "rds:CreateDBCluster",
        "rds:CreateGlobalCluster",
        "rds:RestoreDBInstanceFromS3",
        "rds:RestoreDBClusterFromS3",
      ]
      resources = ["*"]

      condition {
        test     = "Bool"
        variable = "rds:StorageEncrypted"
        values   = [false]
      }
    }
  }
}

resource "aws_organizations_policy" "infrastructure" {
  name        = "infrastructure-policy"
  description = "This policy contains controls to ensure hardening of AWS Infrastructure"
  content     = data.aws_iam_policy_document.infrastructure.json
}

resource "aws_organizations_policy_attachment" "infrastructure" {
  for_each  = toset(var.target_ids)
  policy_id = aws_organizations_policy.infrastructure.id
  target_id = each.value
}
