## Latacora Service Control Policy Recommendations

These are the foundational Service Control Policies (SCPs) that [Latacora](https://www.latacora.com/) recommends putting in place.

### Base Security, Infrastructure, and Governance Controls

These policies are meant to be implemented at the root organizational unit (or at targeted OUs/accounts) to harden the security of the organization, enforce infrastructure best practices, and apply broad governance controls.

The repo is split into three modules, each producing a single SCP:

- `policy-groups/security-best-practices/` — `security-policy`
- `policy-groups/infrastructure-best-practices/` — `infrastructure-policy`
- `policy-groups/governance-best-practices/` — `governance-policy`

Each module is attached independently via its own `target_ids` variable, so different policies can be attached to different OUs or accounts.

Note: these policies may prevent infrastructure from being deployed by IaC tools when the configurations are not compliant with the SCPs.

#### Security Best Practices

This set of SCPs is designed to limit the attack surface of the AWS environment and harden the most important actions that can be taken in an account.

| Service | SCP Statement | Effect | Implementation Reasoning |
| --- | --- | --- | --- |
| Account | DenyLeavingOrgs | Prevents accounts from leaving their organization | Organization account management should only be done by the management account. This SCP prevents member accounts from removing themselves from the Org and becoming standalone AWS accounts. |
| Account (root) | RestrictMemberAccountRootUsers | Denies all actions taken by the member-account root user | We recommend deleting member account root credentials using [centralized root access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html), with this SCP for defense-in-depth. Daily operations should use IAM roles/SSO. |
| CloudTrail | DenyCloudTrailChanges | Denies modifications to CloudTrail trails | Once an organizational trail is correctly configured (ideally shipping to a separate Log Archive account), this SCP ensures trails cannot be deleted, stopped, or have their event selectors altered, protecting log integrity. |
| Billing | DenyBillingChanges | Blocks changes to billing, payments, invoicing, purchase orders, tax registrations, and financing applications | Billing, tax, and payment options should be managed in the management account for the organization. |
| Account | DenyAccountChanges | Blocks modifications to account contacts, primary email, and region enable/disable | Account settings should be managed by the management account. |

#### Infrastructure Best Practices

This set of SCPs ensures that infrastructure created in the account meets best practices at a service level.

| Service | SCP Statement | Effect | Implementation Reasoning |
| --- | --- | --- | --- |
| EC2 | RequireIMDSv2 | Prevents EC2 instances from being created unless `ec2:MetadataHttpTokens` is required | IMDSv1 allows an SSRF-vulnerable app to steal instance credentials from the metadata service. IMDSv2 mitigates that risk. |
| EC2 | DenyIMDSChanges | Prevents modifying EC2 instance metadata options | Paired with RequireIMDSv2 so the configuration cannot be downgraded to v1. See [our blog post on IMDSv1](https://www.latacora.com/blog/2021/08/11/remediating-aws-imdsv1/) before enabling. |
| EC2 | RequireEBSEncryption | Prevents creating EBS volumes unless encryption is enabled | Encrypts data at rest and in transit between an instance and its EBS volumes. |
| S3 | RequireS3BucketHTTPS | Denies any S3 API request where `aws:SecureTransport` is false | Forces TLS; prevents eavesdropping and MITM on S3 traffic. |
| S3 | DenyPublicAccesstoS3Buckets | Prevents modifying the S3 Account-level Public Access Block | Preserves a safe default against accidental public buckets. |
| RDS | DenyUnencryptedRDS | Prevents creating or restoring an RDS/Aurora/Neptune/DocumentDB instance or cluster unless storage encryption is enabled | Enforces at-rest encryption across create and restore paths, regardless of engine. |

#### Governance Best Practices

Broad, org-wide guardrails that are governance-oriented rather than directly security-related.

| Service | SCP Statement | Effect | Implementation Reasoning |
| --- | --- | --- | --- |
| Global | EnabledRegions | Denies API calls outside the specified regions | Takes a list of allowed regions and blocks everything else. Global services (IAM, CloudFront, Route53, STS, etc.) are exempted, as is the `AWSControlTowerExecution` role. |

### Deployment

Terraform Version: > 1.0.0

#### Usage

Consume this repo as a Terraform module. We recommend pinning `source` to a specific commit SHA (not a branch or tag) so the policies applied to your organization are reproducible and can only change through an intentional bump:

```hcl
module "scps" {
  source = "git::https://github.com/latacora/latacora-service-control-policies.git?ref=<full-40-char-sha>"

  security_policy_target_ids       = ["r-abcd"]
  infrastructure_policy_target_ids = ["ou-abcd-workloads"]
  governance_policy_target_ids     = ["r-abcd"]

  enabled_regions = ["us-east-1", "us-west-2"]
}
```

Why pin to a SHA rather than a tag or branch:

- Tags can be moved; branches change on every push. Either can silently alter which SCPs are attached to your org.
- SCPs are high-blast-radius controls — an unreviewed change here can break production or weaken guardrails.
- A SHA pin makes upgrades an explicit, reviewable PR: bump the `ref=`, run `terraform plan`, inspect the diff, merge.

#### Required / notable variables

Defined in [`variables.tf`](/variables.tf):

- `security_policy_target_ids` — list of organization roots, OUs, or accounts to attach `security-policy` to
- `infrastructure_policy_target_ids` — targets for `infrastructure-policy`
- `governance_policy_target_ids` — targets for `governance-policy`
- `enabled_regions` — list of allowed regions for the governance region-deny policy. **Defaults to `["us-east-1"]`** so callers don't accidentally lock themselves out; override in real deployments.
- `enable_security_policy`, `enable_infrastructure_policy`, `enable_governance_policy` — bool toggles for each module (all default to `true`)

Each target list is independent, so you can (for example) attach the security and governance SCPs to the entire org root while scoping the infrastructure SCP to a workload OU:

```hcl
security_policy_target_ids        = ["r-abcd"]
governance_policy_target_ids      = ["r-abcd"]
infrastructure_policy_target_ids  = ["ou-abcd-workloads"]
```

#### Disabling individual statements

Each module has per-statement bool variables in its `variables.tf` (e.g. `deny_cloudtrail_changes`, `require_imdsv2`). Flip one to `false` to drop that statement from the compiled policy. This is also the mechanism for temporarily disabling a control — set false, apply, make the change, set true, apply again. (For example, disabling `deny_imds_change` while migrating instances from IMDSv1 to v2.)

#### Deployment

- Run `terraform plan` first and review the output.
- `terraform apply` deploys all enabled modules.
- To deploy a single policy group: `terraform apply --target=module.security_scp` (or `.infrastructure_scp`, or `.governance_scp`).
- To remove: `terraform destroy` (or `--target=...` for a single module).

Note: This assumes valid AWS credentials for the management account (where SCPs are managed) and basic familiarity with Terraform and state management. Since everything in this module is SCP configuration, losing state is recoverable.

#### SCP size limit

AWS Organizations enforces a 5,120-character limit per SCP. The three-module split keeps each policy well under that ceiling, with headroom to add statements.

### References

Although these are the Latacora recommended SCPs, we did not come up with them all alone. We used resources available on blogs, documentation sites, and AWS official user guides to craft our recommendations.

- https://cloudsecdocs.com/aws/devops/resources/scps/
- https://asecure.cloud/p/scp_package/
- https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/
- https://github.com/ScaleSec/terraform_aws_scp/tree/main/security_controls_scp
- https://github.com/trussworks/terraform-aws-ou-scp
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html
- https://docs.aws.amazon.com/controltower/latest/userguide/primary-region-deny-policy.html

### Feedback

Feedback is always welcome. If you run into issues, please open a GitHub issue and we'll take a look!
