## Latacora Service Control Policy Recommendations 
There are three groups of Serive Control Policies that latacora recommends putting in place that map closely to IG1 and IG3 from the Security Architecture Review Process. 

### IG 1 - Base Security and Infrastructure Configuration Controls 
These Policies are meant to be implemented at the root organizational unit as they will harden the security of the account as well as enforce security best practices when it comes to the infrastructure that is being deployed. 

#### Security Best Practices
This security hardening focused set of SCPs is designed to limit the attack surface of the AWS environment as well as harden the most important actions that can be taken in an account. 

This policy includes: 
* Disabling an account from leaving the organization
* Disabling changes being made to the Organizational Cloudtrail Trail
* Enabling only regions that are meant to be used

#### Infrastructure Configuration Controls
This set of SCPs is more focused on ensuring that the infrastructure that gets created in the account meets best practices at a service level. 
Note: These policies may prevent infrastructure from being deployed by IaC tools when the configurations are not complete with the correct settings enabled. 

This policy includes: 
 * EC2
    * Require Instance Metadata Service V2 
    * EBS Volumes are encrypted
    * EBS Snapshots are encrypted 
 * S3
    * Require object Encryption
    * Default S3 Encryption Enabled
    * Bucket policy requires HTTPS
    * Buckets are not public
 * RDS
    * RDS Snapshots are encrypted

### IG 3 - Specialized SCPs 
These policies will be specific to the needs to the environment...
