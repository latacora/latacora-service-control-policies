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
| Account (root) | RestrictMemberAccountRootUsers | Denies all actions taken with member-account root user credentials. Sessions from [centralized root access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html) (`sts:AssumeRoot`) are not denied. | We recommend deleting member account root credentials using centralized root access, with this SCP for defense-in-depth. The exemption uses the `aws:AssumedRoot` key, as [AWS recommends](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html#condition-keys-assumedroot), so privileged tasks run from the management account still work. Daily operations should use IAM roles/SSO. |
| CloudTrail | DenyCloudTrailChanges | Denies modifications to CloudTrail trails | Once an organizational trail is correctly configured (ideally shipping to a separate Log Archive account), this SCP ensures trails cannot be deleted, stopped, or have their event selectors altered, protecting log integrity. |
| Billing | DenyBillingChanges | Blocks changes to billing, payments, invoicing, purchase orders, tax registrations, and financing applications | Billing, tax, and payment options should be managed in the management account for the organization. |
| Account | DenyAccountChanges | Blocks modifications to account contacts, primary email, and region enable/disable | Account settings should be managed by the management account. |

#### Infrastructure Best Practices

This set of SCPs ensures that infrastructure created in the account meets best practices at a service level.

| Service | SCP Statement | Effect | Implementation Reasoning |
| --- | --- | --- | --- |
| EC2 | RequireIMDSv2 | Prevents EC2 instances from being created unless `ec2:MetadataHttpTokens` is required | IMDSv1 allows an SSRF-vulnerable app to steal instance credentials from the metadata service. IMDSv2 mitigates that risk. |
| EC2 | DenyIMDSChanges | Prevents modifying EC2 instance metadata options | Paired with RequireIMDSv2 so the configuration cannot be downgraded to v1. See [our blog post on IMDSv1](https://www.latacora.com/blog/2021/08/11/remediating-aws-imdsv1/) before enabling. |
| EC2 | RequireEBSEncryption | Prevents creating unencrypted EBS volumes, either directly or when launching an instance (including root volumes from unencrypted AMIs) | Encrypts data at rest and in transit between an instance and its EBS volumes. Pair with [EBS encryption by default](https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html) in each region, and test launches from existing AMIs and launch templates in a non-production account before rolling out. |
| EC2 | DenyEbsEncryptionByDefaultChanges | Prevents disabling EBS encryption by default | EBS encryption by default is a per-account, per-region setting that EC2 declarative policies don't support, so enable it in each account and region first (e.g. with `aws_ebs_encryption_by_default`). This SCP keeps it from being switched off. |
| S3 | RequireS3BucketHTTPS | Denies any S3 API request where `aws:SecureTransport` is false | Forces TLS; prevents eavesdropping and MITM on S3 traffic. |
| S3 | DenyPublicAccesstoS3Buckets | Prevents modifying the S3 Account-level Public Access Block | Preserves a safe default against accidental public buckets. |
| RDS | DenyUnencryptedRDS | Prevents creating or restoring an RDS or Aurora instance or cluster unless storage encryption is enabled | Enforces at-rest encryption across create and restore paths. |

#### Governance Best Practices

Broad, org-wide guardrails that are governance-oriented rather than directly security-related.

| Service | SCP Statement | Effect | Implementation Reasoning |
| --- | --- | --- | --- |
| Global | EnabledRegions | Denies API calls outside the specified regions | Takes a list of allowed regions and blocks everything else. Global services (IAM, CloudFront, Route53, STS, etc.) are exempted, as is the `AWSControlTowerExecution` role. |

### Deployment

Terraform version: 1.1.0 or later (for `moved` blocks).

#### Usage

Consume this repo as a Terraform module, pinned to the commit SHA of a release tag. Keep the tag in a comment so readers and reviewers can see which release it is:

```hcl
module "scps" {
  # v1.0.0
  source = "git::https://github.com/latacora/latacora-service-control-policies.git?ref=<full-40-char-sha-of-v1.0.0>"

  security_policy_target_ids       = ["r-abcd"]
  infrastructure_policy_target_ids = ["ou-abcd-workloads"]
  governance_policy_target_ids     = ["r-abcd"]

  enabled_regions = ["us-east-1", "us-west-2"]
}
```

#### Versions and pinning

Releases use [semantic versioning](https://semver.org/) and are listed on the [releases page](https://github.com/latacora/latacora-service-control-policies/releases) and in [`CHANGELOG.md`](/CHANGELOG.md):

- **Major** (`v2.0.0`): changes you must act on, such as renamed variables, new required inputs, or `moved` blocks you need to add.
- **Minor** (`v1.1.0`): new statements or stricter conditions. These can deny actions that were allowed before, so read the changelog and review the plan before upgrading.
- **Patch** (`v1.0.1`): fixes that make existing statements work as documented.

Pick a release by its version, then pin to that release's commit SHA rather than the tag name. Each release's notes list its SHA, or you can look it up:

```sh
gh api repos/latacora/latacora-service-control-policies/commits/v1.0.0 --jq .sha
# or, without the GitHub CLI (use the line ending in ^{} if there is one):
git ls-remote --tags https://github.com/latacora/latacora-service-control-policies.git 'v1.0.0*'
```

Why a SHA rather than the tag or a branch:

- SCPs are high-blast-radius controls; an unreviewed change here can break production or weaken guardrails.
- A branch changes on every push. A tag can be moved to a different commit, so `?ref=v1.0.0` isn't guaranteed to fetch the same code tomorrow. A SHA can only ever mean one commit.
- With a SHA pin, every upgrade is an explicit, reviewable change: pick the new release, update the SHA and the version comment, run `terraform plan`, review the diff, merge.

#### Required / notable variables

Defined in [`variables.tf`](/variables.tf):

- `security_policy_target_ids` — list of organization roots, OUs, or accounts to attach `security-policy` to
- `infrastructure_policy_target_ids` — targets for `infrastructure-policy`
- `governance_policy_target_ids` — targets for `governance-policy`
- `enabled_regions` — **required.** List of allowed regions for the governance region-deny policy. There is no default, so you have to choose your regions; include `us-east-1` to avoid locking out global-service endpoints.
- `enable_security_policy`, `enable_infrastructure_policy`, `enable_governance_policy` — bool toggles for each module (all default to `true`)

Each target list is independent, so you can (for example) attach the security and governance SCPs to the entire org root while scoping the infrastructure SCP to a workload OU:

```hcl
security_policy_target_ids        = ["r-abcd"]
governance_policy_target_ids      = ["r-abcd"]
infrastructure_policy_target_ids  = ["ou-abcd-workloads"]
```

#### Disabling individual statements

Each module has per-statement bool variables in its `variables.tf` (e.g. `deny_cloudtrail_changes`, `require_imdsv2`). Flip one to `false` to drop that statement from the compiled policy. This is also the mechanism for temporarily disabling a control — set false, apply, make the change, set true, apply again. (For example, disabling `deny_imds_change` while migrating instances from IMDSv1 to v2.)

These variables are on the policy-group modules, not the root module. To set them, call the policy-group module directly, e.g. `source = "git::https://github.com/latacora/latacora-service-control-policies.git//policy-groups/security-best-practices?ref=<release-sha>"`, pinned the same way as above.

#### Deployment

- Run `terraform plan` first and review the output.
- `terraform apply` deploys all enabled modules.
- To deploy a single policy group: `terraform apply --target=module.security_scp` (or `.infrastructure_scp`, or `.governance_scp`).
- To remove: `terraform destroy` (or `--target=...` for a single module).

Note: This assumes valid AWS credentials for the management account (where SCPs are managed) and basic familiarity with Terraform and state management. Since everything in this module is SCP configuration, losing state is recoverable.

#### Upgrading from the two-module layout

Previous versions had two modules — `security_scp` and `infrastructure_scp` — each taking a single `target_ou_id` string. The current layout adds the `governance_scp` module (region deny, previously embedded in the security policy) and switches each module's attachment from a single `target_ou_id` to a `target_ids` list attached via `for_each`.

Resources in each module are now named after their policy group:

| Module | Old address (inside the module) | New address |
| --- | --- | --- |
| `security_scp` | `aws_organizations_policy.security_hardened_policy` | `aws_organizations_policy.security` |
| `security_scp` | `aws_organizations_policy_attachment.policy_attachment` | `aws_organizations_policy_attachment.security["<target-id>"]` |
| `infrastructure_scp` | `aws_organizations_policy.infrastructure_hardened_policy` | `aws_organizations_policy.infrastructure` |
| `infrastructure_scp` | `aws_organizations_policy_attachment.policy_attachment` | `aws_organizations_policy_attachment.infrastructure["<target-id>"]` |
| `governance_scp` | (new) | `aws_organizations_policy.governance`, `aws_organizations_policy_attachment.governance["<target-id>"]` |

The policy renames are handled by `moved` blocks shipped in each module, so no action is needed for them. The `aws_iam_policy_document` data sources were also renamed, but data sources are re-read on every plan and don't need `moved` blocks.

**Attachments need a `moved` block in your root config.** Each attachment is now created with `for_each`, keyed by target ID. The key comes from your input, so the module can't ship a `moved` block for it. Without one, Terraform destroys the old attachment before creating the new one, which leaves that SCP detached (and its denies unenforced) for the length of the apply. Add one `moved` block per module you had attached, keyed by the ID you used to pass as `target_ou_id`. Adjust `module.scps` to whatever you named the module in your config:

```hcl
moved {
  from = module.scps.module.security_scp[0].aws_organizations_policy_attachment.policy_attachment
  to   = module.scps.module.security_scp[0].aws_organizations_policy_attachment.security["r-abcd"]
}

moved {
  from = module.scps.module.infrastructure_scp[0].aws_organizations_policy_attachment.policy_attachment
  to   = module.scps.module.infrastructure_scp[0].aws_organizations_policy_attachment.infrastructure["ou-abcd-workloads"]
}
```

The governance module is new, so it needs no `moved` block.

You will also need to update your root config: replace each module's `target_ou_id = "..."` with `*_policy_target_ids = ["..."]`, and (if region-deny was in use) add `governance_policy_target_ids` plus `enabled_regions`.

Before applying, check the plan:

- The policies and existing attachments should show as moved, not destroyed. Any `destroy` on an `aws_organizations_policy_attachment` means a `moved` block is missing or has the wrong key.
- If you used the region deny, it moves from `security-policy` to the new `governance-policy`. Both changes happen in the same apply, so there can be a short window where neither policy has it. To avoid that, apply the governance module first (`terraform apply -target=module.scps.module.governance_scp`), then run a full apply.

#### Behavior changes in v1.0.0

Besides the layout change, these change what the policies allow or deny compared with the last two-module version. Review them against your environment before applying:

- `RestrictMemberAccountRootUsers` no longer denies [centralized root access](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html) sessions (`sts:AssumeRoot`).
- `RequireEBSEncryption` now also covers volumes created by `RunInstances`, including root volumes from AMIs with unencrypted snapshots. Turn on EBS encryption by default in each account and region first, or launches from those AMIs will fail.
- New statement: `DenyEbsEncryptionByDefaultChanges`.
- `DenyCloudtrailChanges` also denies `cloudtrail:PutEventSelectors` and `cloudtrail:PutInsightSelectors`.
- `DenyBillingChanges` and `DenyAccountChanges` replace the legacy `aws-portal:*` actions with the current billing, payments, tax, invoicing and account actions, and now also deny region opt-in changes and contact and primary-email updates in member accounts.

#### SCP size limit

AWS Organizations allows up to [10,240 characters per SCP](https://docs.aws.amazon.com/organizations/latest/userguide/org_troubleshoot_policies.html), and when a policy is created through the API, whitespace counts. Splitting along security / infrastructure / governance lines keeps each policy well under that and makes intent explicit, leaving plenty of headroom to add statements.

### References

Although these are the Latacora recommended SCPs, we did not come up with them all alone. We used resources available on blogs, documentation sites, and AWS official user guides to craft our recommendations.

- https://cloudsecdocs.com/aws/devops/resources/scps/
- https://asecure.cloud/p/scp_package/
- https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/
- https://github.com/ScaleSec/terraform_aws_scp/tree/main/security_controls_scp
- https://github.com/trussworks/terraform-aws-ou-scp
- https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html
- https://docs.aws.amazon.com/controltower/latest/controlreference/primary-region-deny-policy.html

### Feedback

Feedback is always welcome. If you run into issues, please open a GitHub issue and we'll take a look!
