moved {
  from = data.aws_iam_policy_document.combined_policy_block
  to   = data.aws_iam_policy_document.this
}

moved {
  from = aws_organizations_policy.infrastructure_hardened_policy
  to   = aws_organizations_policy.this
}
