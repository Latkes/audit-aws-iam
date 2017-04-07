audit IAM
============================
This stack will monitor IAM and alert on things CloudCoreo developers think are violations of best practices


## Description
This repo is designed to work with CloudCoreo. It will monitor IAM against best practices for you and send a report to the email address designated by the config.yaml AUDIT&#95;AWS&#95;IAM&#95;ALERT&#95;RECIPIENT value


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
  * description: Which alerts would you like to check for? Default is all IAM alerts. Choices are iam-inventory-users, iam-inventory-roles, iam-inventory-policies, iam-inventory-groups, iam-unusediamgroup, iam-multiple-keys, iam-inactive-key-no-rotation, iam-active-key-no-rotation, iam-passwordreuseprevention, iam-missing-password-policy, iam-expirepasswords, iam-no-mfa, iam-root-active-password, iam-user-attached-policies, iam-password-policy-uppercase, iam-password-policy-lowercase, iam-password-policy-symbol, iam-password-policy-number, iam-password-policy-min-length, iam-root-access-key-1, iam-root-access-key-2, iam-active-root-user, iam-mfa-password-holders, iam-support-role, iam-user-password-not-used, iam-cloudbleed-passwords-not-rotated, iam-unused-access, iam-root-key-access, iam-root-no-mfa, iam-initialization-access-key, iam-no-hardware-mfa-root
  * default: iam-inventory-users, iam-inventory-roles, iam-inventory-policies, iam-inventory-groups, iam-unusediamgroup, iam-multiple-keys, iam-inactive-key-no-rotation, iam-active-key-no-rotation, iam-passwordreuseprevention, iam-missing-password-policy, iam-expirepasswords, iam-no-mfa, iam-root-active-password, iam-user-attached-policies, iam-password-policy-uppercase, iam-password-policy-lowercase, iam-password-policy-symbol, iam-password-policy-number, iam-password-policy-min-length, iam-root-access-key-1, iam-root-access-key-2, iam-active-root-user, iam-mfa-password-holders, iam-support-role, iam-user-password-not-used, iam-cloudbleed-passwords-not-rotated, iam-unused-access, iam-root-key-access, iam-root-no-mfa, iam-initialization-access-key, iam-no-hardware-mfa-root


## Optional variables with no default

### `AUDIT_AWS_IAM_ALERT_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `AUDIT_AWS_IAM_ACCOUNT_NUMBER`:
  * description: The AWS account number. Required for a full CIS audit. This can be found by the root user at https://console.aws.amazon.com/billing/home?#/account

## Tags
1. Audit
1. Best Practices
1. Alert
1. IAM

## Categories
1. Audit



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-iam/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-iam/master/images/icon.png "icon")

