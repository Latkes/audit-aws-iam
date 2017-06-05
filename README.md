iam audit
============================
This composite monitors iam and reports best practice violations, standards body policy violations, and inventory


## Description
This composite monitors iam against best practices and reports violations and inventory


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-iam/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_IAM_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_IAM_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_IAM_DAYS_PASSWORD_UNUSED`:
  * description: Number of days for which password has not been used
  * default: 30


## Optional variables with default

### `AUDIT_AWS_IAM_ALERT_LIST`:
  * description: Which rules would you like to run? Possible values are iam-inventory-users iam-inventory-roles iam-inventory-policies iam-inventory-groups iam-unusediamgroup iam-multiple-keys iam-root-multiple-keys iam-inactive-key-no-rotation iam-active-key-no-rotation iam-missing-password-policy iam-passwordreuseprevention iam-expirepasswords iam-no-mfa iam-root-active-password iam-user-attached-policies iam-password-policy-uppercase iam-password-policy-lowercase iam-password-policy-symbol iam-password-policy-number iam-password-policy-min-length iam-root-access-key-1 iam-root-access-key-2 iam-cloudbleed-passwords-not-rotated iam-support-role iam-user-password-not-used iam-unused-access iam-no-hardware-mfa-root iam-active-root-user iam-mfa-password-holders manual-ensure-security-questions manual-detailed-billing iam-root-key-access iam-root-no-mfa manual-strategic-iam-roles iam-initialization-access-key manual-contact-details manual-security-contact manual-resource-instance-access manual-full-privilege-user manual-appropriate-sns-subscribers manual-least-access-routing-tables
  * default: iam-unusediamgroup, iam-multiple-keys, iam-root-multiple-keys, iam-inactive-key-no-rotation, iam-active-key-no-rotation, iam-missing-password-policy, iam-passwordreuseprevention, iam-expirepasswords, iam-no-mfa, iam-root-active-password, iam-user-attached-policies, iam-password-policy-uppercase, iam-password-policy-lowercase, iam-password-policy-symbol, iam-password-policy-number, iam-password-policy-min-length, iam-root-access-key-1, iam-root-access-key-2, iam-cloudbleed-passwords-not-rotated, iam-support-role, iam-user-password-not-used, iam-unused-access, iam-no-hardware-mfa-root, iam-active-root-user, iam-mfa-password-holders, manual-ensure-security-questions, manual-detailed-billing, iam-root-key-access, iam-root-no-mfa, manual-strategic-iam-roles, iam-initialization-access-key, manual-contact-details, manual-security-contact, manual-resource-instance-access, manual-full-privilege-user, manual-appropriate-sns-subscribers, manual-least-access-routing-tables, manual-obscure-auth-info, manual-least-access-routing-tables, manual-maintenance-records, manual-approved-monitored-maintenance, manual-component-removal-approval


## Optional variables with no default

### `AUDIT_AWS_IAM_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `AUDIT_AWS_IAM_ACCOUNT_NUMBER`:
  * description: The AWS account number. Required for a full CIS audit. This can be found by the root user at https://console.aws.amazon.com/billing/home?#/account

## Tags
1. Audit
1. Best Practices
1. Inventory
1. iam


## Categories
1. AWS Services Audit


## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-iam/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-iam/master/images/icon.png "icon")

