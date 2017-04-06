coreo_aws_rule "iam-inventory-users" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM User Inventory"
  description "This rule performs an inventory on all IAM Users in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["users"]
  audit_objects ["object.users.user_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.users.user_name"
end 

coreo_aws_rule "iam-inventory-roles" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Role Inventory"
  description "This rule performs an inventory on all IAM Roles in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["roles"]
  audit_objects ["object.roles.role_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.roles.role_name"
end

coreo_aws_rule "iam-inventory-policies" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Policy Inventory"
  description "This rule performs an inventory on all IAM Policies in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["policies"]
  audit_objects ["object.policies.policy_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.policies.policy_name"
end

coreo_aws_rule "iam-inventory-groups" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_elb-inventory.html"
  include_violations_in_count false
  display_name "IAM Group Inventory"
  description "This rule performs an inventory on all IAM User Groups in the target AWS account."
  category "Inventory"
  suggested_action "None."
  level "Informational"
  objectives ["groups"]
  audit_objects ["object.groups.group_name"]
  operators ["=~"]
  raise_when [//]
  id_map "object.groups.group_name"
end

coreo_aws_rule "iam-unusediamgroup" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "Unused or empty IAM group"
  description "There is an IAM group defined without any users in it and therefore unused."
  category "Access"
  suggested_action "Ensure that groups defined within IAM have active users in them. If the groups don't have active users or are not being used, delete the unused IAM group."
  level "Warning"
  objectives ["groups", "group"]
  call_modifiers [{}, {:group_name => "groups.group_name"}]
  formulas ["", "count"]
  audit_objects ["", "users"]
  operators ["", "=="]
  raise_when ["", 0]
  id_map "object.group.group_name"
end

coreo_aws_rule "iam-multiple-keys" do
  action :define
  service :iam
  # link "http://kb.cloudcoreo.com/mydoc_iam-unusediamgroup.html"
  display_name "IAM User with multiple keys"
  description "There is an IAM User with multiple access keys"
  category "Access"
  suggested_action "Remove excess access keys"
  level "Warning"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.access_key_1_active", "object.content.access_key_2_active"]
  operators ["=~", "=~" ]
  raise_when [/true/i, /true/i]
end

coreo_aws_rule "iam-inactive-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-inactive-key-no-rotation.html"
  display_name "User Has Access Keys Inactive and Un-rotated"
  description "User has inactive keys that have not been rotated in the last 90 days."
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Critical"
  id_map "modifier.user_name"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
  operators ["", "==", "<"]
  raise_when ["", "Inactive", "90.days.ago"]
end

coreo_aws_rule "iam-active-key-no-rotation" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-active-key-no-rotation.html"
  display_name "User Has Access Keys Active and Un-rotated"
  description "User has active keys that have not been rotated in the last 90 days"
  category "Access"
  suggested_action "If you regularly use the AWS access keys, we recommend that you also regularly rotate or delete them."
  level "Critical"
  meta_cis_id "1.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "modifiers.user_name"
  objectives ["users", "access_keys", "access_keys"]
  audit_objects ["", "access_key_metadata.status", "access_key_metadata.create_date"]
  call_modifiers [{}, {:user_name => "users.user_name"}, {:user_name => "users.user_name"}]
  operators ["", "==", "<"]
  raise_when ["", "Active", "90.days.ago"]
end

coreo_aws_rule "iam-missing-password-policy" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't exist"
  description "There currently isn't a password policy to require a certain password length, password expiration, prevent password reuse, and more."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  level "Critical"
  objectives ["account_password_policy"]
  audit_objects ["object"]
  operators ["=="]
  raise_when [nil]
  id_map "static.password_policy"
end

coreo_aws_rule "iam-passwordreuseprevention" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-passwordreuseprevention.html"
  display_name "Users can reuse old passwords"
  description "The current password policy doesn't prevent users from reusing thier old passwords."
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.10"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Critical"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object"]
  operators ["=~"]
  raise_when [/euse/]
end

coreo_aws_rule "iam-expirepasswords" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-expirepasswords.html"
  display_name "Passwords not set to expire"
  description "The current password policy doesn't require users to regularly change their passwords. User passwords are set to never expire."
  category "Access"
  suggested_action "Configure a strong password policy for your users so that passwords expire such that users must change their passwords periodically."
  meta_cis_id "1.11"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Critical"
  objectives ["account_password_policy"]
  audit_objects ["object.password_policy.expire_passwords"]
  operators ["=="]
  raise_when ["false"]
  id_map "static.password_policy"
end

coreo_aws_rule "iam-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled"
  description "Cloud user does not have Multi-Factor Authentication enabled on their cloud account."
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for every cloud user."
  level "Critical"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.password_enabled", "object.content.mfa_active"]
  operators ["=~", "=~" ]
  raise_when [/true/i, /false/i]
end

coreo_aws_rule "iam-root-active-password" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
  display_name "Root user has active password"
  description "The root user has been logging in using a password."
  category "Security"
  suggested_action "Re-set your root account password, don't log in to your root account, and secure root account password in a safe place."
  level "Critical"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.password_last_used"]
  operators ["==", ">"]
  raise_when ["<root_account>", "15.days.ago"]
end

coreo_aws_rule "iam-user-attached-policies" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-user-attached-policies.html"
  display_name "Account using inline policies"
  description "User account is using custom inline policies versus using IAM group managed policies."
  category "Access"
  suggested_action "Switch all inline policies to apply to IAM groups and assign users IAMs roles."
  meta_cis_id "1.16"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  id_map "modifiers.user_name"
  objectives ["users", "user_policies"]
  formulas ["", "count"]
  call_modifiers [{}, {:user_name => "users.user_name"}]
  audit_objects ["", "object.policy_names"]
  operators ["", ">"]
  raise_when ["", 0]
end

coreo_aws_rule "iam-password-policy-uppercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require an uppercase letter"
  description "The password policy must require an uppercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_uppercase_characters"]
  operators ["=="]
  raise_when [false]
end

coreo_aws_rule "iam-password-policy-lowercase" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require an lowercase letter"
  description "The password policy must require an lowercase letter to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_lowercase_characters"]
  operators ["=="]
  raise_when [false]
end

coreo_aws_rule "iam-password-policy-symbol" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a symbol"
  description "The password policy must require a symbol to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.7"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_symbols"]
  operators ["=="]
  raise_when [false]
end

coreo_aws_rule "iam-password-policy-number" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a number"
  description "The password policy must require a number to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.require_numbers"]
  operators ["=="]
  raise_when [false]
end

coreo_aws_rule "iam-password-policy-min-length" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-missing-password-policy.html"
  display_name "Password policy doesn't require a minimum length of 14 characters"
  description "The password policy must require a minimum length of 14 characters to meet CIS standards"
  category "Access"
  suggested_action "Configure a strong password policy for your users to ensure that passwords expire, aren't reused, have a certain length, require certain characters, and more."
  meta_cis_id "1.9"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["account_password_policy"]
  id_map "static.password_policy"
  audit_objects ["object.password_policy.minimum_password_length"]
  operators ["<"]
  raise_when [14]
end

coreo_aws_rule "iam-root-access-key-1" do
  action :define
  service :iam
  link ""
  display_name "Root Access Key Exists - Key #1"
  description "Root Access Key #1 exists. Ideally, the root account should not have any active keys."
  category "Security"
  suggested_action "Do not use Root Access Keys. Consider deleting the Root Access keys and using IAM users instead."
  level "Warning"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.access_key_1_active"]
  operators ["==", "=="]
  raise_when ["<root_account>", true]
end

coreo_aws_rule "iam-root-access-key-2" do
  action :define
  service :iam
  link ""
  display_name "Root Access Key Exists - Key #2"
  description "Root Access Key #2 exists. Ideally, the root account should not have any active keys."
  category "Security"
  suggested_action "Do not use Root Access Keys. Consider deleting the Root Access keys and using IAM users instead."
  level "Warning"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.access_key_2_active"]
  operators ["==", "=="]
  raise_when ["<root_account>", true]
end

coreo_aws_rule "iam-cloudbleed-passwords-not-rotated" do
  action :define
  service :iam
  display_name "User may have been exposed to the CloudBleed issue"
  description "Cloudbleed is the latest internet bug that puts users private information in jeopardy. News of the bug broke late on Feb 24, 2017,"
  link "http://kb.cloudcoreo.com/mydoc_iam-cloudbleed-password-not-rotated.html"
  category "Security"
  suggested_action "Users should be asked to rotate their passwords after February 25, 2017"
  level "Critical"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report", "credential_report"]
  audit_objects ["object.content.password_last_changed", "object.content.password_last_changed", "object.content.password_last_changed"]
  operators ["!=", "!=", "<"]
  raise_when ["not_supported", "N/A", "2017-02-21 16:00:00 -0800"]
end

coreo_aws_rule "iam-support-role" do
  action :define
  service :iam
  display_name "IAM Support Role"
  description "Ensure a support role exists to manage incidents"
  category "Security"
  suggested_action "Create a support role"
  meta_cis_id "1.22"
  meta_cis_scored "true"
  meta_cis_level "1"
  level "Warning"
  objectives ["", "policies"]
  audit_objects ["object.policies.policy_name", "object.policies.attachment_count"]
  operators ["==", ">"]
  raise_when ["AWSSupportAccess", 0]
  id_map "object.policies.policy_name"
end

coreo_aws_rule "iam-user-password-not-used" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-user-password-not-used.html"
  include_violations_in_count false
  display_name "IAM User Password Not Used Recently"
  description "Lists all IAM users whose password has not used in ${AUDIT_AWS_IAM_DAYS_PASSWORD_UNUSED} days"
  category "Security"
  suggested_action "Consider deleting unused or unnecessary IAM users"
  level "Informational"
  objectives ["users"]
  audit_objects ["object.users.password_last_used"]
  operators ["<"]
  raise_when ['${AUDIT_AWS_IAM_DAYS_PASSWORD_UNUSED}.days.ago']
  id_map "object.users.user_name"
end

coreo_aws_rule "iam-unused-access" do
  action :define
  service :user
  include_violations_in_count false   
  display_name "IAM inactive credentials"
  description "This rule checks for credentials that have been unused for 90 days"
  category "Inventory"
  suggested_action "User credentials that have not been used in 90 days should be removed or deactivated"
  level "Warning"
  meta_cis_id "1.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end


coreo_aws_rule "iam-no-hardware-mfa-root" do
  action :define
  service :iam
  display_name "IAM has no root MFA hardware devices"
  description "Triggers if there is no hardware MFA Device for root"
  category "Security"
  suggested_action "Establish a hardware MFA device for root"
  meta_cis_id "1.14"
  meta_cis_scored "true"
  meta_cis_level "2"
  level "Critical"
  objectives ["virtual_mfa_devices"]
  audit_objects ["object.virtual_mfa_devices.serial_number"]
  operators ["=="]
  raise_when ["arn:aws:iam::${AUDIT_AWS_IAM_ACCOUNT_NUMBER}:mfa/root-account-mfa-device"]
  id_map "object.virtual_mfa_devices.user.user_name"
end

coreo_aws_rule "iam-active-root-user" do
  action :define
  service :iam
  include_violations_in_count false
  display_name "IAM Root User Activity"
  description "This rule performs an audit on root user activity"
  category "Inventory"
  suggested_action "Root user should not be active, when possible. Additionally, ensure that CIS rule 3.3 is passing for this rule to pass"
  level "Informational"
  meta_cis_id "1.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=="]
  raise_when ["<root_account>"]
end

coreo_aws_rule "iam-mfa-password-holders" do
  action :define
  service :iam
  include_violations_in_count false
  display_name "MFA for IAM Password Holders"
  description "This rule checks that all IAM users with a password have MFA enabled"
  category "Security"
  suggested_action "Activate MFA for all users with a console password"
  level "Warning"
  meta_cis_id "1.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives ["credential_report","credential_report"]
  audit_objects ["object.content.password_enabled", "object.content.mfa_active"]
  operators ["==", "=="]
  raise_when [true, false]
  id_map "object.content.user"
end

coreo_aws_rule "manual-ensure-security-questions" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=40"
  display_name "Ensure Account Security Questions"
  description "Security Questions improve account security"
  category "Security"
  suggested_action "Ensure that the AWS account has security questions registered"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-detailed-billing" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=44"
  display_name "Enable Detailed Billing"
  description "Detailed billing can help to bring attention to anomalous use of AWS resources"
  category "Security"
  suggested_action "Ensure that Detailed Billing has been enabled"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.17"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-root-key-access" do
  action :define
  service :user
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Security"
  suggested_action "Deactivate root access keys"
  level "Informational"
  meta_cis_id "1.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-root-no-mfa" do
  action :define
  service :user
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "Warning"
  meta_cis_id "1.13"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "manual-strategic-iam-roles" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=47"
  display_name "Ensure Strategic IAM Roles"
  description "Use IAM Master and Manager Roles to optimise security"
  category "Security"
  suggested_action "Implement IAM roles as set out in the CIS document"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.18"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "iam-initialization-access-key" do
  action :define
  service :user
  display_name "IAM Initialization Access"
  description "This rule checks for access keys that were activated during initialization"
  category "Inventory"
  suggested_action "Do not establish access keys during initialization of user"
  level "Warning"
  meta_cis_id "1.23"
  meta_cis_scored "false"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "manual-contact-details" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=59"
  display_name "Maintain Contact Details"
  description "Contact details associated with the AWS account may be used by AWS staff to contact the account owner"
  category "Security"
  suggested_action "Ensure that contact details associated with AWS account are current"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.19"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-security-contact" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=61"
  display_name "Security Contact Details"
  description "Contact details may be provided to the AWS account for your security team, allowing AWS staff to contact them when required"
  category "Security"
  suggested_action "Ensure that security contact information is provided in your AWS account"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.20"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-resource-instance-access" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=62"
  display_name "IAM Instance Roles"
  description "Proper usage of IAM roles reduces the risk of active, unrotated keys"
  category "Security"
  suggested_action "Ensure IAM instance roles are used for AWS resource access from instances"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.21"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-full-privilege-user" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=69"
  display_name "IAM Full Privileges"
  description "IAM users should not be granted full privileges"
  category "Security"
  suggested_action "Ensure no IAM user has full '*' privileges"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "1.24"
  meta_cis_scored "true"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
end

coreo_aws_rule "manual-appropriate-sns-subscribers" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=130"
  display_name "SNS Appropriate Subscribers"
  description "Unintended SNS subscribers may pose a security risk"
  category "Security"
  suggested_action "Regularly ensure that only appropriate subscribers exist in SNS"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "3.15"
  meta_cis_scored "false"
  meta_cis_level "1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

coreo_aws_rule "manual-least-access-routing-tables" do
  action :define
  service :user
  link "https://benchmarks.cisecurity.org/tools2/amazon/CIS_Amazon_Web_Services_Foundations_Benchmark_v1.1.0.pdf#page=141"
  display_name "Least Access Routing Tables"
  description "Being highly selective in peering routing tables minimizes impact of potential breach"
  category "Security"
  suggested_action "Review and minimize routing table access regularly"
  level "Informational"
  meta_always_show_card "true"
  meta_cis_id "4.5"
  meta_cis_scored "false"
  meta_cis_level "2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [""]
  id_map "static.no_op"
end

# end of user-visible content. Remaining resources are system-defined

coreo_aws_rule "iam-internal" do
  action :define
  service :iam
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  meta_cis_id "1.23"
  meta_cis_scored "false"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_uni_util_variables "iam-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-iam" do
  service :iam
  action :run
  rules ${AUDIT_AWS_IAM_ALERT_LIST}.push("iam-internal")
end

coreo_uni_util_variables "iam-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.report'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},

            ])
end

coreo_uni_util_jsrunner "cis-iam" do
  action :run
  data_type "json"
  provide_composite_access true
  json_input '{ "composite name":"PLAN::stack_name",
                "violations":COMPOSITE::coreo_aws_rule_runner.advise-iam.report}'
  function <<-EOH

  const ruleMetaJSON = {
       'iam-unused-access': COMPOSITE::coreo_aws_rule.iam-unused-access.inputs,
       'iam-root-key-access': COMPOSITE::coreo_aws_rule.iam-root-key-access.inputs,
       'iam-root-no-mfa': COMPOSITE::coreo_aws_rule.iam-root-no-mfa.inputs,
       'iam-initialization-access-key': COMPOSITE::coreo_aws_rule.iam-initialization-access-key.inputs
   };
   const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
   const ruleMeta = {};
 
   Object.keys(ruleMetaJSON).forEach(rule => {
       const flattenedRule = {};
       ruleMetaJSON[rule].forEach(input => {
           if (ruleInputsToKeep.includes(input.name))
               flattenedRule[input.name] = input.value;
       })
       ruleMeta[rule] = flattenedRule;
   })

   const UNUSED_ACCESS_RULE = 'iam-unused-access'
   const ROOT_ACCESS_RULE = 'iam-root-key-access'
   const ROOT_MFA_RULE = 'iam-root-no-mfa'
   const INIT_ACCESS_RULE = 'iam-initialization-access-key'

let alertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
let alertListArray = alertListToJSON.replace(/'/g, '"');
const users = json_input['violations']['us-east-1'];

function setValueForNewJSONInput(json_input) {

    //if cis 1.3 wanted, the below will run
    if  (alertListArray.indexOf('iam-unused-access') > -1) {
        for (var user in users) {
          if (users[user].hasOwnProperty('violator_info')) {
            var keyOneDate = new Date(users[user]['violator_info']['access_key_1_last_used_date']);
            var keyTwoDate = new Date(users[user]['violator_info']['access_key_2_last_used_date']);
            var passwordUsedDate = new Date(users[user]['violator_info']['password_last_used']);
            const ninetyDaysAgo = (new Date()) - 1000 * 60 * 60 * 24 * 90

            const keyOneUnused = keyOneDate < ninetyDaysAgo
            const keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true"
            const keyTwoUnused = keyTwoDate < ninetyDaysAgo
            const keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true"
            const passwordUnused = passwordUsedDate < ninetyDaysAgo
            const passwordEnabled = users[user]['violator_info']['password_enabled'] == "true"

            if ((keyOneUnused && keyOneEnabled) || (keyTwoEnabled && keyTwoUnused) || (passwordEnabled && passwordUnused)) {

                if (!json_input['violations']['us-east-1'][user]) {
                    json_input['violations']['us-east-1'][user] = {}
                }
                if (!json_input['violations']['us-east-1'][user]['violations']) {
                    json_input['violations']['us-east-1'][user]['violations'] = {}
                }
                json_input['violations']['us-east-1'][user]['violations']['iam-unused-access'] = Object.assign(ruleMeta[UNUSED_ACCESS_RULE]);
            }
          }
        }
    }

    //if cis 1.12 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-key-access') > -1) {
        const keyOneEnabled = users["<root_account>"]['violator_info']['access_key_1_active'] == "false"
        const keyTwoEnabled = users["<root_account>"]['violator_info']['access_key_2_active'] == "false"

        if ((keyOneEnabled || keyTwoEnabled)) {

            if (!json_input['violations']['us-east-1']["<root_account>"]) {
                json_input['violations']['us-east-1']["<root_account>"] = {}
            }
            if (!json_input['violations']['us-east-1']["<root_account>"]['violations']) {
                json_input['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            json_input['violations']['us-east-1']["<root_account>"]['violations']['iam-root-access_key'] = Object.assign(ruleMeta[ROOT_ACCESS_RULE]);
        }
    }

    //if cis 1.13 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-no-mfa') > -1) {
        if (users["<root_account>"]['violator_info']['mfa_active'] == "false"){

            if (!json_input['violations']['us-east-1']["<root_account>"]) {
                json_input['violations']['us-east-1']["<root_account>"] = {}
            }
            if (!json_input['violations']['us-east-1']["<root_account>"]['violations']) {
                json_input['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            json_input['violations']['us-east-1']["<root_account>"]['violations']['iam-root-no-mfa'] = Object.assign(ruleMeta[ROOT_MFA_RULE]);
        }
    }


    //if cis 1.23 wanted, the below will run
    if  (alertListArray.indexOf('iam-initialization-access-key') > -1) {
        for (var user in users) {
          if (users[user].hasOwnProperty('violator_info')) {
            var keyOneDate = users[user]['violator_info']['access_key_1_last_used_date'] == "N/A";
            var keyTwoDate = users[user]['violator_info']['access_key_2_last_used_date'] == "N/A";
            var keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true";
            var keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true";

            if ((keyOneDate && keyOneEnabled) || (keyTwoDate && keyTwoEnabled)) {

                if (!json_input['violations']['us-east-1'][user]) {
                    json_input['violations']['us-east-1'][user] = {}
                }
                if (!json_input['violations']['us-east-1'][user]['violations']) {
                    json_input['violations']['us-east-1'][user]['violations'] = {}
                }
                json_input['violations']['us-east-1'][user]['violations']['iam-initialization-access-key'] = Object.assign(ruleMeta[INIT_ACCESS_RULE]);
            }
          }
        }
    }

    //Strip internal violations
    for (var user in users) {
        var internal = users[user]['violations'].hasOwnProperty('iam-internal');
        var single_violation = (Object.keys(users[user]['violations']).length === 1);

        if (internal && single_violation) {
            delete json_input['violations']['us-east-1'][user];
        }
        else if (internal && !single_violation){
            delete json_input['violations']['us-east-1'][user]['violations']['iam-internal'];
        }
    }
}

setValueForNewJSONInput(json_input)

const violations = json_input['violations'];
const report = JSON.stringify(violations)

coreoExport('JSONReport', JSON.stringify(json_input));
coreoExport('report', report);

callback(violations);
  EOH
end


coreo_uni_util_variables "iam-update-planwide-4" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.report'},
            ])
end

coreo_uni_util_jsrunner "tags-to-notifiers-array-iam" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-9"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-iam.report}'
  function <<-EOH
  

function setTableAndSuppression() {
  let table;
  let suppression;

  const fs = require('fs');
  const yaml = require('js-yaml');
  try {
      suppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading suppression.yaml file`);
      suppression = {};
  }
  try {
      table = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
      console.log(`Error reading table.yaml file`);
      table = {};
  }
  coreoExport('table', JSON.stringify(table));
  coreoExport('suppression', JSON.stringify(suppression));
  
  let alertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
  let alertListArray = alertListToJSON.replace(/'/g, '"');
  json_input['alert list'] = alertListArray || [];
  json_input['suppression'] = suppression || [];
  json_input['table'] = table || {};
}


setTableAndSuppression();

const JSON_INPUT = json_input;
const NO_OWNER_EMAIL = "${AUDIT_AWS_IAM_ALERT_RECIPIENT}";
const OWNER_TAG = "NOT_A_TAG";
const ALLOW_EMPTY = "${AUDIT_AWS_IAM_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_IAM_SEND_ON}";
const SHOWN_NOT_SORTED_VIOLATIONS_COUNTER = false;

const SETTINGS = { NO_OWNER_EMAIL, OWNER_TAG,
     ALLOW_EMPTY, SEND_ON, SHOWN_NOT_SORTED_VIOLATIONS_COUNTER};

const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');
const AuditIAM = new CloudCoreoJSRunner(JSON_INPUT, SETTINGS);

const newJSONInput = AuditIAM.getSortedJSONForAuditPanel();
coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', JSON.stringify(newJSONInput['violations']));


const letters = AuditIAM.getLetters();
callback(letters);
  EOH
end

coreo_uni_util_variables "iam-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.table'}
            ])
end

coreo_uni_util_jsrunner "iam-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.return'
  function <<-EOH

const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        if(hasEmail) {
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['num_violations'] + "\\n";
        }
    });

    textRollup += 'Number of Violating Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;
}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-iam-to-tag-values" do
  action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.return'
end

coreo_uni_util_notify "advise-iam-rollup" do
  action((("${AUDIT_AWS_IAM_ALERT_RECIPIENT}".length > 0) and (!"NOT_A_TAG".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_IAM_ALLOW_EMPTY}
  send_on '${AUDIT_AWS_IAM_SEND_ON}'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.iam-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_IAM_ALERT_RECIPIENT}', :subject => 'PLAN::stack_name New Rollup Report for PLAN::name plan from CloudCoreo'
  })
end
