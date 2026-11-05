# Renames from the two-module layout. Data sources are re-read on every
# plan and need no moved block, so only the managed policy is listed. The
# attachment changed to for_each and is moved from the root config (see README).
moved {
  from = aws_organizations_policy.infrastructure_hardened_policy
  to   = aws_organizations_policy.infrastructure
}
