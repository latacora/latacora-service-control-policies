locals {
  require_imdsv2_statement               = var.require_imdsv2 ? [""] : []
  deny_imds_change_statement             = var.deny_imds_change ? [""] : []
  require_ebs_encryption_statement       = var.require_ebs_encryption ? [""] : []
  require_s3_object_encryption_statement = var.require_s3_object_encryption ? [""] : []
  require_s3_bucket_https_statement      = var.require_s3_bucket_https ? [""] : []
  deny_s3_public_access_statement        = var.deny_s3_public_access ? [""] : []
  require_rds_encryption_statement       = var.require_rds_encryption ? [""] : []
}

data "aws_iam_policy_document" "combined_policy_block" {

  dynamic "statement" {
    for_each = local.require_imdsv2_statement
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
    for_each = local.deny_imds_change_statement
    content {
      sid       = "DenyIMDSChanges"
      effect    = "Deny"
      actions   = ["ec2:ModifyInstanceMetadataOptions"]
      resources = ["*"]
    }
  }

  dynamic "statement" {
    for_each = local.require_ebs_encryption_statement
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
    for_each = local.require_s3_object_encryption_statement
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
    for_each = local.require_s3_bucket_https_statement
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
    for_each = local.deny_s3_public_access_statement
    content {
      sid       = "DenyPublicAccesstoS3Buckets"
      effect    = "Deny"
      actions   = ["s3:PutAccountPublicAccessBlock"]
      resources = ["*"]
    }

  }

  dynamic "statement" {
    for_each = local.require_rds_encryption_statement
    content {
      sid       = "DenyNotAuroraDBInstance"
      effect    = "Deny"
      actions   = ["rds:CreateDBInstance", ]
      resources = ["*"]

      condition {
        test     = "ForAnyValue:StringEquals"
        variable = "rds:DatabaseEngine"
        values = [
          "mariadb",
          "mysql",
          "oracle-ee",
          "oracle-se2",
          "oracle-se1",
          "oracle-se",
          "postgres",
          "sqlserver-ee",
          "sqlserver-se",
          "sqlserver-ex",
        "sqlserver-web"]
      }

      condition {
        test     = "Bool"
        variable = "rds:StorageEncrypted"
        values   = [false]
      }

    }

  }

  dynamic "statement" {
    for_each = local.require_rds_encryption_statement
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

