# Cloud credential playbooks

## How to revoke a leaked AWS access key
Deactivate the key first so nothing using it keeps working, then delete it: `aws iam update-access-key --user-name <USER> --access-key-id <KEY_ID> --status Inactive`, then `aws iam delete-access-key --user-name <USER> --access-key-id <KEY_ID>`. Create a replacement with `aws iam create-access-key --user-name <USER>` and update every deployment that used the old one. `aws iam get-access-key-last-used --access-key-id <KEY_ID>` shows when and where the key was last used.

## What to check after an AWS key leak
Look for persistence the attacker may have created: new access keys (`aws iam list-access-keys`), new IAM users, login profiles, attached policies, and roles with changed trust policies. Look for running EC2 instances in every region, not only your usual one, since attackers often mine cryptocurrency in unused regions. Review CloudTrail with `aws cloudtrail lookup-events --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=<KEY_ID>`. S3 object reads only appear if S3 data events were enabled on a trail.

## How to revoke a leaked Google Cloud service account key
List the account's keys with `gcloud iam service-accounts keys list --iam-account=<SERVICE_ACCOUNT_EMAIL>` and delete the leaked one with `gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SERVICE_ACCOUNT_EMAIL>`. The key ID is the private_key_id field of the leaked JSON file. Prefer Workload Identity or attached service accounts over downloaded key files so there is no file to leak.

## What to check after a Google Cloud or Firebase key leak
Review Cloud Audit Logs with `gcloud logging read 'protoPayload.authenticationInfo.principalEmail="<SERVICE_ACCOUNT_EMAIL>"'`. Admin Activity logs are always on; Data Access logs (object reads) are off by default, so reads may be invisible. Check for new service-account keys, changed IAM bindings, new Compute Engine instances and changed Firebase security rules. A Firebase admin SDK key is a Google Cloud service account key with full admin rights over the Firebase project.

## How to revoke a leaked Azure client secret or service principal
List the app's credentials with `az ad app credential list --id <CLIENT_ID>` and delete the leaked one with `az ad app credential delete --id <CLIENT_ID> --key-id <KEY_ID>`. `az ad app credential reset --id <CLIENT_ID>` issues a new secret. For a leaked storage account connection string, rotate the account key: `az storage account keys renew --account-name <ACCOUNT> --resource-group <GROUP> --key key1`.

## What to check after an Azure credential leak
Review the Activity Log with `az monitor activity-log list --caller <CLIENT_ID>`. It covers control-plane operations only: reading a blob does not appear unless diagnostic settings were configured on the storage account beforehand. Check for new role assignments, new app credentials, and virtual machines or other resources created during the exposure window.

## How to remove a secret from git history
Deleting the line in a new commit is not enough: the secret stays readable in history and in every fork and clone. Rotate the credential first, then rewrite history with `git filter-repo --replace-text <replacements.txt>` (or the BFG Repo-Cleaner) and force-push. Ask GitHub Support to clear cached views if needed. Rotation is what actually protects you; history rewriting only limits further exposure.

## How to prevent the next leak
Keep secrets out of code: use environment variables, a secrets manager or your CI's secret store, and add `.env` files to `.gitignore`. Enable GitHub secret scanning and push protection on the repository so a secret is blocked before it is pushed. Prefer short-lived credentials (roles, workload identity) over long-lived keys.
