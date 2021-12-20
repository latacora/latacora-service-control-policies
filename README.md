## Latacora Service Control Policy Recommendations

There are three groups of Service Control Policies (SCPs) that [Latacora](https://www.latacora.com/) recommends putting in place. These SCPs map closely to IG1 and IG3 from the Security Architecture Review Process. 

### IG 1 - Base Security and Infrastructure Configuration Controls

These Policies are meant to be implemented at the root organizational unit as they will harden the security of the account as well as enforce security best practices when it comes to the infrastructure that is being deployed. 

#### Security Best Practices

This set of SCPs is designed to limit the attack surface of the AWS environment as well as to harden the most important actions that can be taken in an account. 

This module includes the following SCPs:

| Service     | SCP Name    | Effect | Implementation Reasoning|
| ----------- | ----------- | ------ | ----------------------- | 
| Account     | DenyLeavingOrgs |     Prevents accounts from being able to leave their organization | Organization account management should only be done by the management account. This includes actions such as adding or removing accounts from the Organization. This SCP prevents member accounts from having the ability to remove themselves from the Org and becoming a standalone AWS account. 
| CloudTrail   | DenyCloudTrailChanges | Denies CloudTrail configuration changes | This policy is meant to be implemented after an organizational CloudTrail has been configured correctly. Latacora recommends configuring the trail to send these logs to a separate Log Archive account where permission is tightly controlled. Once the trail has been set up, implement this SCP to ensure that no changes can be made to protect the integrity of the logs. 
| Global | EnabledRegions | Denies all AWS Regions not specified in the SCP | This policy takes a list of AWS Regions as input and will disable all API calls taken outside of the specified regions. This policy is a little verbose as it must exclude global services from the SCP. 
| Billing     | DenyBillingChanges | Blocks changes to the billing and cost management settings as well as changes to the payment methods | Billing and payment options should be managed in the management account for the organization.
| Account     | DenyAccountChanges | Blocks modifications to the account settings | Account settings should be managed by the Management account. 

#### Infrastructure Best Practices

This set of SCPs ensures that the infrastructure that gets created in the account meets best practices at a service level. 

Note: These policies may prevent infrastructure from being deployed by IaC tools when the configurations are not complete with the correct settings enabled. 

This module includes the following SCPs: 
| Service     | SCP Name    | Effect | Implementation Reasoning|
| ----------- | ----------- | ------ | ----------------------- | 
| EC2         | RequireIMDSv2 | Prevents EC2 instances from being created unless `ec2:MetadataHttpTokens` is required | IMDSv1 comes with security risks through which attackers are able to steal temporary credentials that are available via the instance metadata service. This is only applicable if there is an ssrf vulnerability in the application. IMDSv2 is the more secure version of metadata service that mitigates the risk posed by v1. 
| EC2         | DenyIMDSChanges | Prevents modifying EC2 instance metadata options | In conjunction with requiring IMDSv2, this statement ensures that the IMDS configuration can’t be changed to enable IMDSv1. This will lock the EC2 metadata options as they are, so check out https://latacora.micro.blog/2021/08/11/remediating-aws-imdsv.html to learn more about this issue before deployment. 
| EC2         | RequireEBSEncryption | Prevents creating EC2 volumes unless encryption is enabled | Enabling encryption of EBS volumes ensures that data is encrypted both at-rest and in-transit, specifically between an instance and its attached EBS storage. This may prevent an attacker that gains access to the underlying physical storage systems where this data is hosted from accessing the data associated with the instance. Encryption of this data may also be a requirement in certain compliance regimes.
| S3          | RequireObjectEncryption | Prevents adding objects to S3 buckets unless the objects have encryption enabled | Enabling encryption of S3 objects ensures that data-at-rest is protected. Even if an attacker gains physical access to the underlying storage system that hosts the data for the S3 bucket, encrypted objects would still require a key to be decrypted. One of the primary reasons to enable encryption at-rest in S3 is to meet the requirements of different compliance regimes. 
| S3          | DenyPublicAccesstoS3Buckets | Prevents changes to the Block Public Access S3 setting | The Block Public Access setting is a preventative measure to stop users from accidentally creating public S3 buckets (via ACLs or IAM policies). It can be configured either at the AWS Account level, or for individual buckets. By default, no block is enforced. It is recommended to enable this feature at the Account level for all Accounts within your Organization, and to implement this SCP to prevent any changes to the setting. When a bucket needs to be made public, a temporary exception should be configured to the policy while the change is being made.
| S3          | RequireS3BucketHTTPS | Deny any S3 API request where aws:SecureTransport is set to false | If HTTPS is not enforced, communication between clients and S3 buckets may not be encrypted in transit and is vulnerable to eavesdropping and man-in-the-middle attacks. This SCP prevents unencrypted HTTP requests for S3 buckets in order to protect information from being transmitted over cleartext. 
| RDS         | RequireRDSEncryption | Prevents creating an RDS database instance or cluster unless encryption is enabled for the database storage volumes | Enabling encryption of RDS instance volumes ensures that data is encrypted at rest. This may prevent an attacker that gains access to the underlying physical storage systems where this data is hosted from accessing the data associated with the instance. Encryption of this data may also be a requirement in certain compliance regimes.

### IG 3 - Specialized SCPs

These policies will be specific to the needs to the environment. For now, we will not be releasing these as they require more input and surrounding infrastucture. You can expect them in the future.

### Deployment

We have created this Terraform repository in order to speed up the deployment process of these SCPs. 

Terraform Version: 1.0.0

##### [Required Variables](/variables.tf)

* `target_ou_id`: What OU are you attaching the SCPs to?  
* `enabled_regions`: A list of regions that you want to allow resources to be deployed in. For example: `["us-east-1", "us-west-2"]`  

##### Disabling policy statement

In order to disable specific policy statements in the SCP, change the default type in the variables.tf file inside the [security](/policy-groups/security-best-practices/variables.tf) or [infrastructure](/policy-groups/infrastructure-best-practices/variables.tf) folders from `true` to `false` in the variable block associated with the policy statement that needs to be disabled. 

This is also how you can temporarily disable policy statements. Change a variable to false, redeploy, make the needed changes, change to true, deploy again. (Such as disabling the `deny_imds_change` policy in order to change your instances from using imds v1 to v2)

##### Running the deployment

Steps:

* It is recommended to run `terraform plan` before applying and check over the output to verify it is what you expect.
* To deploy all policy groups to the target SCP, run: `terraform apply` in the root directory of the repository and enter in the required variables listed above.  
* To deploy a single policy group, you can use terraform targeting. For example: `terraform apply --target=module.security_scp`
* If you would like to remove all SCPs, run `terraform destroy` Similarly for targeted modules `terraform destroy --target=module.security_scp`

Note: This comes with the assumption that you have valid AWS credentials to the Management account where SCPs are managed. It also assumes you know a bit about terraform and storing state, but in the case of this module it's all SCP related so not too bad if you have to destroy things if the state gets lost. 

### References
Although these are the Latacora recommended SCPs, we did not come up with them all alone. We used resources available on blogs, documentation sites, and AWS official user guides to craft our recommendations. There are many more SCPs available linked below and we encourage you to check them out.  
* https://cloudsecdocs.com/aws/devops/resources/scps/
* https://asecure.cloud/p/scp_package/
* https://summitroute.com/blog/2020/03/25/aws_scp_best_practices/
* https://github.com/ScaleSec/terraform_aws_scp/tree/main/security_controls_scp
* https://github.com/trussworks/terraform-aws-ou-scp
* https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps_examples.html

### Feedback

Feedback is always welcome. If you run into issues feel free to open a GitHub issue and we will take a look.
