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
  audit_objects ["object.password_policy.password_reuse_prevention"]
  operators [">"]
  raise_when [0]
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

coreo_aws_rule "iam-root-no-mfa" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "Emergency"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report"]
  audit_objects ["object.content.user", "object.content.mfa_active"]
  operators ["==", "=="]
  raise_when ["<root_account>", false]
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

coreo_aws_rule "iam-root-active-key" do
  action :nothing
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-key.html"
  display_name "DEPRICATED - Root user has active Access Key"
  description "DEPRICATED - Root user has an Access Key that is active."
  category "Security"
  suggested_action "DEPRICATED - Replace the root Access Key with an IAM user access key, and then disable and remove the root access key."
  level "Critical"
  id_map "object.user"
  objectives ["credential_report"]
  formulas ["CSV[user=<root_account>]"]
  audit_objects ["object.content.access_key_1_active"]
  operators ["=="]
  raise_when ["true"]
end

coreo_aws_rule "iam-root-access-key-1" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
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

coreo_aws_rule "iam-root-access-key-1" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
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
  link "http://kb.cloudcoreo.com/mydoc_iam-root-active-password.html"
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
  link "https://www.cnet.com/how-to/cloudbleed-bug-everything-you-need-to-know/"
  category "Security"
  suggested_action "Users should be asked to rotate their passwords after February 25, 2017"
  level "Critical"
  id_map "object.content.user"
  objectives ["credential_report", "credential_report", "credential_report"]
  audit_objects ["object.content.password_last_changed", "object.content.password_last_changed", "object.content.password_last_changed"]
  operators ["!=", "!=", "<"]
  raise_when ["not_supported", "N/A", "2017-02-25 00:00:00 -0800"]
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
  service :iam
  include_violations_in_count false   
  display_name "IAM Root User Activity"
  description "This rule performs an inventory on all users using credential report"
  category "Inventory"
  suggested_action "User credentials that have not been used in 90 days should be removed or deactivated"
  level "Informational"
  meta_cis_id "1.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_aws_rule "iam-root-access_key" do
  action :define
  service :iam
  include_violations_in_count false   
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Inventory"
  suggested_action "Deactivate root access keys"
  level "Informational"
  meta_cis_id "1.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_aws_rule "iam-root-no-mfa-cis" do
  action :define
  service :iam
  link "http://kb.cloudcoreo.com/mydoc_iam-root-no-mfa.html"
  display_name "Multi-Factor Authentication not enabled for root account"
  description "Root cloud user does not have Multi-Factor Authentication enabled on their cloud account"
  category "Security"
  suggested_action "Enable Multi-Factor Authentication for the root cloud user."
  level "Emergency"
  meta_cis_id "1.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  id_map "object.content.user"
  objectives ["credential_report"]
  audit_objects ["object.content.user"]
  operators ["=~"]
  raise_when [//]
end

coreo_aws_rule "iam-initialization-access-key" do
  action :define
  service :iam
  include_violations_in_count false
  display_name "IAM Root Access Key"
  description "This rule checks for root access keys. Root account should not have access keys enabled"
  category "Inventory"
  suggested_action "Deactivate root access keys"
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




coreo_aws_rule "iam-internal" do
  action :define
  service :iam
  include_violations_in_count false
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
  audit_objects ["object"]
  operators ["=="]
  raise_when [true]
end



coreo_uni_util_variables "iam-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => 'unset'}
            ])
end

coreo_aws_rule_runner "advise-iam" do
  service :iam
  action :run
  rules ${AUDIT_AWS_IAM_ALERT_LIST}
end

coreo_uni_util_variables "iam-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.report'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.advise-iam.number_violations'},

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
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.report'},
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-iam.table'}
            ])
end

coreo_uni_util_jsrunner "cis-iam" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.9.2"
               },
               ])
  json_input '{ "composite name":"PLAN::stack_name",
                "plan name":"PLAN::name",
                "cloud account name": "PLAN::cloud_account_name",
                "violations":COMPOSITE::coreo_aws_rule_runner.advise-iam.report}'
  function <<-EOH
  
function copyPropForNewJsonInput() {
    newJSONInput['composite name'] = json_input['composite name'];
    newJSONInput['cloud account name'] = json_input['cloud account name'];
    return newJSONInput;
}

let alertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
let alertListArray = alertListToJSON.replace(/'/g, '"');
const newJSONInput = {}
newJSONinput = copyPropForNewJsonInput();
newJSONInput['violations'] = {}
newJSONInput['violations']['us-east-1'] = {}
const users = json_input['violations']['us-east-1'];

function setValueForNewJSONInput() {

  const unusedCredsMetadata = {
        'service': 'iam',
        'display_name': 'IAM Unused credentials',
        'description': 'Checks for unused credentials',
        'category': 'Audit',
        'suggested_action': 'User credentials that have not been used in 90 days should be removed or deactivated',
        'level': 'Warning',
        'meta_cis_id': '1.3',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
  };

    const rootMFAMetadata = {
        'service': 'iam',
        'display_name': 'Root MFA disabled',
        'description': 'Checks root MFA status',
        'category': 'Audit',
        'suggested_action': 'Root MFA should be enabled',
        'level': 'Warning',
        'meta_cis_id': '1.13',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
    };

    const rootAccessMetadata = {
        'service': 'iam',
        'display_name': 'IAM Root Access Key',
        'description': 'IAM Root Access Key',
        'category': 'Audit',
        'suggested_action': 'IAM Root Access Key',
        'level': 'Warning',
        'meta_cis_id': '1.12',
        'meta_cis_scored': 'true',
        'meta_cis_level': '1'
    };

    const initAccessMetadata = {
        'service': 'iam',
        'display_name': 'IAM Init Access',
        'description': 'IAM Init Access Key',
        'category': 'Audit',
        'suggested_action': 'IAM Init Access Key',
        'level': 'Warning',
        'meta_cis_id': '1.23',
        'meta_cis_scored': 'false',
        'meta_cis_level': '1'
    };

    //if cis 1.3 wanted, the below will run
    if  (alertListArray.indexOf('iam-unused-access') > -1) {
        for (var user in users) {
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

                if (!newJSONInput['violations']['us-east-1'][user]) {
                    newJSONInput['violations']['us-east-1'][user] = {}
                }
                ;
                if (!newJSONInput['violations']['us-east-1'][user]['violations']) {
                    newJSONInput['violations']['us-east-1'][user]['violations'] = {}
                }
                ;
                newJSONInput['violations']['us-east-1'][user]['violations']['iam-unused-access'] = unusedCredsMetadata
            }
        }
    }

    //if cis 1.12 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-access-key') > -1) {
        const keyOneEnabled = users["<root_account>"]['violator_info']['access_key_1_active'] == "false"
        const keyTwoEnabled = users["<root_account>"]['violator_info']['access_key_2_active'] == "false"

        if ((keyOneEnabled || keyTwoEnabled)) {

            if (!newJSONInput['violations']['us-east-1']["<root_account>"]) {
                newJSONInput['violations']['us-east-1']["<root_account>"] = {}
            }
            ;
            if (!newJSONInput['violations']['us-east-1']["<root_account>"]['violations']) {
                newJSONInput['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            ;
            newJSONInput['violations']['us-east-1']["<root_account>"]['violations']['iam-root-access_key'] = rootAccessMetadata
        }
    }

    //if cis 1.13 wanted, the below will run
    if  (alertListArray.indexOf('iam-root-no-mfa-cis') > -1) {
        if (users["<root_account>"]['violator_info']['mfa_active'] == "false"){

            if (!newJSONInput['violations']['us-east-1']["<root_account>"]) {
                newJSONInput['violations']['us-east-1']["<root_account>"] = {}
            }
            ;
            if (!newJSONInput['violations']['us-east-1']["<root_account>"]['violations']) {
                newJSONInput['violations']['us-east-1']["<root_account>"]['violations'] = {}
            }
            ;
            newJSONInput['violations']['us-east-1']["<root_account>"]['violations']['iam-root-no-mfa-cis'] = rootMFAMetadata
        }
    }


    //if cis 1.23 wanted, the below will run
    if  (alertListArray.indexOf('iam-initialization-access-key') > -1) {
        for (var user in users) {
            var keyOneDate = users[user]['violator_info']['access_key_1_last_used_date'] == "N/A";
            var keyTwoDate = users[user]['violator_info']['access_key_2_last_used_date'] == "N/A";
            var keyOneEnabled = users[user]['violator_info']['access_key_1_active'] == "true";
            var keyTwoEnabled = users[user]['violator_info']['access_key_2_active'] == "true";

            if ((keyOneDate && keyOneEnabled) || (keyTwoDate && keyTwoEnabled)) {

                if (!newJSONInput['violations']['us-east-1'][user]) {
                    newJSONInput['violations']['us-east-1'][user] = {}
                }
                ;
                if (!newJSONInput['violations']['us-east-1'][user]['violations']) {
                    newJSONInput['violations']['us-east-1'][user]['violations'] = {}
                }
                ;
                newJSONInput['violations']['us-east-1'][user]['violations']['iam-initialization-access-key'] = initAccessMetadata
            }
        }
    }

}

setValueForNewJSONInput()

const violations = newJSONinput['violations'];
const report = JSON.stringify(violations)

coreoExport('JSONReport', JSON.stringify(newJSONInput));
coreoExport('report', report);

callback(violations);
  EOH
end

coreo_uni_util_variables "iam-update-planwide-4" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.iam-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-iam.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis-iam.report'}
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
