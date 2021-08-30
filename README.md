## Latacora Service Control Policy Recommendations 
There are three groups of Serive Control Policies that latacora recommends putting in place that map closely to IG1 and IG3 from the Security Architecture Review Process. 

### IG 1 - Base Security and Infrastructure Configuration Controls 
These Policies are meant to be implemented at the root organizational unit as they will harden the security of the account as well as enforce security best practices when it comes to the infrastructure that is being deployed. 

#### Security Best Practices
This security hardening focused set of SCPs is designed to limit the attack surface of the AWS environment as well as harden the most important actions that can be taken in an account. 

This module includes the following SCPs: 
| Service     | SCP Name    | Effect | Implementation Reasoning|
| ----------- | ----------- | ------ | ----------------------- | 
| Account     | DisableOrgs |     Disable an account from leaving the organization | There are very few cases where you would want to have an AWS Account leave the organization. In those cases it makes sense to temporarily disable the SCP effect from the account in order to make it happen. 
| Cloudtrail   | DisableCloudtrail | Disable changes being made to the Organizational Cloudtrail Trail | Once a separate account has been created and Organizational Cloudtrail has been set up, lock access down so no tampering can be done with the logs

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
| Account     | DisableOrgs |     Disable an account from leaving the organization | There are very few cases where you would want to have an AWS Account leave the organization. In those cases it makes sense to temporarily disable the SCP effect from the account in order to make it happen. 
| Cloudtrail   | DisableCloudtrail | Disable changes being made to the Organizational Cloudtrail Trail | Once a separate account has been created and Organizational Cloudtrail has been set up, lock access down so no tampering can be done with the logs

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
