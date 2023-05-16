data "aws_iam_policy_document" "combined_policy_block" {
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
      sid       = "RequireEBSEncryption"
      effect    = "Deny"
      actions   = ["ec2:CreateVolume", ]
      resources = ["*"]

      condition {
        test     = "Bool"
        variable = "ec2:Encrypted"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = var.require_s3_object_encryption ? [1] : []

    content {
      sid       = "RequireObjectEncryption"
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = ["arn:aws:s3:::*/*"]

      condition {
        test     = "ForAllValues:StringNotEquals"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["AES256", "aws:kms"]
      }

      condition {
        test     = "Null"
        variable = "s3:x-amz-server-side-encryption"
        values   = ["true"]
      }
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
      sid       = "DenyNotAuroraDBInstance"
      effect    = "Deny"
      actions   = ["rds:CreateDBInstance"]
      resources = ["*"]

      condition {
        test     = "ForAnyValue:StringEquals"
        variable = "rds:DatabaseEngine"
        values = [
          "mariadb",
          "mysql",
          "oracle-ee",
          "oracle-se",
          "oracle-se1",
          "oracle-se2",
          "postgres",
          "sqlserver-ee",
          "sqlserver-ex",
          "sqlserver-se",
          "sqlserver-web",
        ]
      }

      condition {
        test     = "Bool"
        variable = "rds:StorageEncrypted"
        values   = [false]
      }
    }
  }

  dynamic "statement" {
    for_each = var.require_rds_encryption ? [1] : []

    content {
      sid       = "DenyAuroraDatabaseCluster"
      effect    = "Deny"
      actions   = ["rds:CreateDBCluster"]
      resources = ["*"]

      condition {
        test     = "Bool"
        variable = "rds:StorageEncrypted"
        values   = [false]
      }
    }
  }
}

resource "aws_organizations_policy" "infrastructure_hardened_policy" {
  name        = "infrastructure-policy"
  description = "This policy contains controls to ensure hardening of AWS Infrastructure"
  content     = data.aws_iam_policy_document.combined_policy_block.json

}

resource "aws_organizations_policy_attachment" "policy_attachment" {
  policy_id = aws_organizations_policy.infrastructure_hardened_policy.id
  target_id = var.target_ou_id
}
