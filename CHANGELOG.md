# Changelog

All notable changes to this repo are listed here. Versions follow
[semantic versioning](https://semver.org/); see "Versions and pinning" in the
[README](README.md) for what each kind of release means for you.

## v1.0.0

First tagged release. Upgrading from an earlier commit needs config changes;
see "Upgrading from the two-module layout" in the README.

### Changed (action needed)

- The SCPs are split into three modules, each producing its own policy:
  `security-policy`, `infrastructure-policy`, and the new `governance-policy`,
  which now holds the region deny that used to be in `security-policy`.
- `target_ou_id` is replaced by `security_policy_target_ids`,
  `infrastructure_policy_target_ids` and `governance_policy_target_ids`,
  so each policy can be attached to multiple roots, OUs or accounts.
- Resources are renamed after their policy group. The module's `moved`
  blocks handle the policies; attachments need a `moved` block in your root
  config (see the README).

### Fixed

- `RestrictMemberAccountRootUsers` no longer blocks centralized root access
  sessions (`sts:AssumeRoot`).
- `RequireEBSEncryption` now also covers volumes created by `RunInstances`,
  including root volumes from AMIs with unencrypted snapshots.
- `DenyBillingChanges` replaces the legacy `aws-portal:*` actions with the
  current billing, payments, tax, invoicing and purchase-order actions.

### Added

- `DenyEbsEncryptionByDefaultChanges` denies turning off EBS encryption by
  default.
- `DenyCloudtrailChanges` also denies `cloudtrail:PutEventSelectors` and
  `cloudtrail:PutInsightSelectors`.
- `DenyAccountChanges` also denies region opt-in changes and contact and
  primary-email updates in member accounts.
- The region deny also exempts `quicksight:DescribeAccountSubscription`.
