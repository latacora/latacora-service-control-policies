## Latacora Service Control Policy Recommendations 
There are three groups of Serive Control Policies that latacora recommends putting in place that map closely to IG1 and IG3 from the Security Architecture Review Process. 

### IG 1 - Base Security and Infrastructure Configuration Controls 
These Policies are meant to be implemented at the root organizational unit as they will harden the security of the account as well as enforce security best practices when it comes to the infrastructure that is being deployed. 

#### Security Best Practices
This security hardening focused set of SCPs is designed to limit the attack surface of the AWS environment as well as harden the most important actions that can be taken in an account. 

This module includes the following SCPs: 
| Service     | SCP Name    | Effect | Implementation Reasoning|
| ----------- | ----------- | ------ | ----------------------- | 
| Account     | DenyLeavingOrgs |     Prevents accounts from being able to leave their organization | Organization account management should only be done by the management account. This includes actions such as adding or removing accounts from the Organization. This SCP prevents member accounts from having the ability to remove themselves from the Org and becoming a standalone AWS account. 
| Cloudtrail   | DenyCloudtrailChanges | Denies Cloudtrail configuration changes | This policy is meant to be implemented after an organizational cloudtrail has been configured correctly. Latacora recommends configuring the trail to send these logs to a separate Log Archive account where permission is tightly controlled. Once the trail has been set up, implement this SCP to ensure that no changes can be made to protect the integrity of the logs. 
| Organizations      | EnabledRegions | Denies all AWS Regions not specified in the SCP | This policy takes a list of AWS Regions as input and will disable all api calls taken outside of the specified regions. This policy is a little verbose as it must exclude global services from the SCP. 
| Billing     | DenyBillingChanges | Blocks changes to the billing and cost management settings as well as changes to the payment methods | Billing and payment options should be managed in the management account for the organization.
| Account     | DenyAccountChanges | Blocks modifications to the account settings | Account settings should be managed by the Management account. 

This policy includes: 
* Disable an account from leaving the organization
* Disable changes being made to the Organizational Cloudtrail Trail
* Enable only regions that are meant to be used
* Disable Billing Changes 
* Disable Account Changes

#### Infrastructure Best Practices
This set of SCPs is more focused on ensuring that the infrastructure that gets created in the account meets best practices at a service level. 
Note: These policies may prevent infrastructure from being deployed by IaC tools when the configurations are not complete with the correct settings enabled. 


This module includes the following SCPs: 
| Service     | SCP Name    | Effect | Implementation Reasoning|
| ----------- | ----------- | ------ | ----------------------- | 
| EC2         | RequireIMDSv2 | Prevents EC2 instances from being created unless ec2:MetadataHttpsTokens is required | IMDSv1 comes with security risks through which attackers are able to steal temporary credentials that are available via the instance metadata service. This is only applicable if there is an ssrf vulnerability in the application.. IMDSv2 is the more secure version of metadata service that mitigates the risk posed by v1. 
| EC2         | DenyIMDSChanges | Prevents modifying EC2 instance metadata options | In conjunction with requiring IMDSv2, this statement ensures that the IMDS configuration can’t be changed to enable IMDSv1.
| EC2         | RequireEBSEncryption | Prevents creating EC2 volumes unless encryption is enabled | Enabling encryption of EBS volumes ensures that data is encrypted both at-rest and in-transit, specifically between an instance and its attached EBS storage. This may prevent an attacker that gains access to the underlying physical storage systems where this data is hosted from accessing the data associated with the instance. Encryption of this data may also be a requirement in certain compliance regimes.
| S3          | RequireObjectEncryption | Prevents adding objects to s3 buckets unless the objects have encryption enabled | Enabling encryption of s3 objects ensures that data-at-rest is protected. Even if an attacker gains physical access to the underlying storage system that hosts the data for the s3 bucket, encrypted objects would still require a key to be decrypted. One of the primary reasons to enable encryption at-rest in s3 is to meet the requirements of different compliance regimes. 
| S3          | DenyPublicAccesstoS3Buckets | Prevents changes to the PublicAccessBlock s3 setting | The PublicAccessBlock setting is a preventative measure to stop users from accidentally creating public s3 buckets. The default of the PublicAccessBlock setting is to completely disable public access and this SCP will prevent any changes to the setting. If a public s3 bucket is needed, this will have to be temporarily disabled which makes public s3 bucket creation very intentional. 
| S3          | RequireS3BucketHTTPS | Deny any s3 API request where aws:SecureTransport is set to false | If HTTPS is not enforced, communication between clients and s3 buckets may not be encrypted in transit and is vulnerable to eavesdropping and man-in-the-middle attacks. This SCP prevents unencrypted HTTP requests for s3 buckets in order to protect information from being transmitted over cleartext. 
| RDS         | RequireRDSEncryption | Prevents creating an RDS database instance or cluster unless encryption is enabled for the database storage volumes | Enabling encryption of RDS instance volumes ensures that data is encrypted at rest. This may prevent an attacker that gains access to the underlying physical storage systems where this data is hosted from accessing the data associated with the instance. Encryption of this data may also be a requirement in certain compliance regimes.

This policy includes: 
 * EC2
    * Require Instance Metadata Service V2 
    * EBS Volumes are encrypted
 * S3
    * Require object encryption
    * Bucket policy requires HTTPS
    * Deny changes to S3 Public Access
 * RDS
    * RDS database encryption is enabled

### IG 3 - Specialized SCPs 
These policies will be specific to the needs to the environment...
