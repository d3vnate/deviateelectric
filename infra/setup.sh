#!/usr/bin/env bash
# =============================================================================
# Deviate Electric — contact-form infrastructure bootstrap
#
# Automates, in order:
#   1. SES sending-identity verification check (+ optional re-send)
#   2. Least-privilege IAM policy + user + access key (SES SendEmail only)
#   3. GCP Secret Manager population (AWS keys + reCAPTCHA secret)
#   4. app.yaml project-ID substitution
#
# Prerequisites:
#   - AWS CLI v2 configured for an admin/IAM-capable profile:
#       aws configure --profile deviate   (or export AWS_PROFILE=deviate)
#   - gcloud CLI authenticated with a project selected:
#       gcloud auth login && gcloud config set project <your-project-id>
#
# Usage:
#   ./infra/setup.sh [--yes]
#     --yes  Non-interactive: assumes "yes" to all prompts (CI-friendly)
#
# Safety:
#   - Idempotent: skips resources that already exist.
#   - Never prints the AWS secret access key; writes it to
#     infra/.secrets/aws_access_key.env (chmod 600) and warns loudly.
# =============================================================================
set -euo pipefail

# ----------------------------- Configuration --------------------------------
readonly SES_REGION="${AWS_SES_REGION:-us-east-2}"
# Named AWS CLI profile holding the `aws login` session (override with AWS_CLI_PROFILE)
export AWS_PROFILE="${AWS_CLI_PROFILE:-deviate-electric}"
readonly SENDER_EMAIL="donny@deviateelectric.com"
readonly IAM_POLICY_NAME="deviateelectric-ses-sendonly"
readonly IAM_USER_NAME="deviateelectric-contact-form"
readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly APP_YAML="$PROJECT_ROOT/app.yaml"
readonly SECRETS_DIR="$PROJECT_ROOT/infra/.secrets"
readonly KEY_FILE="$SECRETS_DIR/aws_access_key.env"

ASSUME_YES=false
[[ "${1:-}" == "--yes" ]] && ASSUME_YES=true

confirm() { # confirm <prompt>
  [[ "$ASSUME_YES" == true ]] && return 0
  read -rp "$prompt [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }

# --------------------------- 0. Preflight checks ----------------------------
step "Preflight: verifying CLIs"
command -v aws >/dev/null   || { echo "ERROR: aws CLI not found"; exit 1; }
command -v gcloud >/dev/null || { echo "ERROR: gcloud CLI not found"; exit 1; }

CALLER_JSON=$(aws sts get-caller-identity)
ACCOUNT_ID=$(jq -r '.Account' <<<"$CALLER_JSON")
ARN_CALLER=$(jq -r '.Arn' <<<"$CALLER_JSON")
echo "AWS caller:  $ARN_CALLER (account $ACCOUNT_ID)"

GCLOUD_PROJECT=$(gcloud config get-value core.project 2>/dev/null || true)
[[ -n "$GCLOUD_PROJECT" ]] || { echo "ERROR: no gcloud project selected (gcloud config set project <id>)"; exit 1; }
echo "GCP project: $GCLOUD_PROJECT"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# --------------------- 1. SES identity verification -------------------------
step "Checking SES identity verification for $SENDER_EMAIL ($SES_REGION)"
STATUS_JSON=$(aws ses get-identity-verification-attributes \
  --identities "$SENDER_EMAIL" --region "$SES_REGION")
VERIFY_STATUS=$(jq -r '.VerificationStatus' <<<"$STATUS_JSON")
echo "Verification status: $VERIFY_STATUS"

if [[ "$VERIFY_STATUS" != "Success" ]]; then
  echo "NOTE: Identity is not verified yet. Until you click the link in the"
  echo "      verification email, SES will reject sends (in sandbox regions,"
  echo "      recipients must also be verified)."
  if confirm "Send/re-send the SES verification email now?"; then
    aws ses verify-email-identity --email-address "$SENDER_EMAIL" --region "$SES_REGION"
    echo "Verification email dispatched to $SENDER_EMAIL — click the link to activate."
  fi
else
  echo "Identity already verified. Continuing."
fi

# ------------------------ 2. IAM policy + user + key --------------------------
step "Ensuring least-privilege IAM policy '$IAM_POLICY_NAME'"
POLICY_DOC_TMP=$(mktemp)
cat > "$POLICY_DOC_TMP" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSendEmailOnly",
      "Effect": "Allow",
      "Action": [
        "ses:SendEmail",
        "ses:SendRawEmail"
      ],
      "Resource": "*"
    }
  ]
}
JSON

if aws iam get-policy --policy-name "$IAM_POLICY_NAME" >/dev/null 2>&1; then
  echo "Policy exists — pushing updated version (non-breaking-change guard skipped)."
  ARN_POLICY=$(aws iam get-policy --policy-name "$IAM_POLICY_NAME" --query 'Policy.Arn' --output text)
  aws iam create-policy-version \
    --policy-arn "$ARN_POLICY" \
    --policy-document "file://$POLICY_DOC_TMP" \
    --set-as-default >/dev/null
else
  ARN_POLICY=$(aws iam create-policy \
    --policy-name "$IAM_POLICY_NAME" \
    --description "Allows the Deviate Electric contact form to send email via SES only" \
    --policy-document "file://$POLICY_DOC_TMP" \
    --query 'Policy.Arn' --output text)
  echo "Created policy: $ARN_POLICY"
fi
rm -f "$POLICY_DOC_TMP"

step "Ensuring IAM user '$IAM_USER_NAME'"
if ! aws iam get-user --user-name "$IAM_USER_NAME" >/dev/null 2>&1; then
  aws iam create-user --user-name "$IAM_USER_NAME" >/dev/null
  echo "Created user: $IAM_USER_NAME"
else
  echo "User already exists."
fi

ATTACHED=$(aws iam list-attached-user-policies --user-name "$IAM_USER_NAME" \
  --query 'AttachedPolicies[].PolicyName' --output text)
if ! grep -qx "$IAM_POLICY_NAME" <<<"$ATTACHED"; then
  aws iam attach-user-policy --user-name "$IAM_USER_NAME" --policy-arn "$ARN_POLICY"
  echo "Attached policy to user."
else
  echo "Policy already attached."
fi

# Deny everything else implicitly (no other policies attached) — belt & braces:
EXTRA_POLICIES=$(grep -vx "$IAM_POLICY_NAME" <<<"$ATTACHED" | tr -d '\t' || true)
if [[ -n "${EXTRA_POLICIES// /}" ]]; then
  echo "WARNING: user has unexpected extra policies: $EXTRA_POLICIES"
fi

step "Creating access key for '$IAM_USER_NAME'"
ACTIVE_KEYS=$(aws iam list-access-keys --user-name "$IAM_USER_NAME" \
  --query 'AccessKeyMetadata[?Status==`Active`].UserName' --output text || true)
if [[ -n "${ACTIVE_KEYS// /}" ]]; then
  echo "An ACTIVE access key already exists for this user."
  if confirm "Delete the old active key(s) and rotate to a fresh one?"; then
    OLD_IDS=$(aws iam list-access-keys --user-name "$IAM_USER_NAME" \
      --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text)
    for kid in $OLD_IDS; do
      aws iam deactivate-access-key --user-name "$IAM_USER_NAME" --access-key-id "$kid"
      sleep 1
      aws iam delete-access-key --user-name "$IAM_USER_NAME" --access-key-id "$kid"
      echo "Rotated away old key $kid"
    done
  else
    echo "Keeping existing key. Skipping key creation."
    ACCESS_KEY_ID=""
    SKIP_GCP_AWS_SECRETS=true
  fi
fi

ACCESS_KEY_ID=""
SKIP_GCP_AWS_SECRETS=${SKIP_GCP_AWS_SECRETS:-false}
if [[ "$SKIP_GCP_AWS_SECRETS" != true ]]; then
  KEY_JSON=$(aws iam create-access-key --user-name "$IAM_USER_NAME")
  ACCESS_KEY_ID=$(jq -r '.AccessKey.AccessKeyId' <<<"$KEY_JSON")
  SECRET_ACCESS_KEY=$(jq -r '.AccessKey.SecretAccessKey' <<<"$KEY_JSON")

  umask 077
  cat > "$KEY_FILE" <<ENV
# Generated by infra/setup.sh on $(date -u +%FT%TZ)
# DO NOT COMMIT THIS FILE. It contains live AWS credentials.
export AWS_ACCESS_KEY_ID=$ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$SECRET_ACCESS_KEY
export AWS_SES_REGION=$SES_REGION
ENV
  rm -f "$KEY_JSON"
  echo "Access key $ACCESS_KEY_ID stored in $KEY_FILE (chmod 600)."
  echo "!! The secret access key appears NOWHERE ELSE. If lost, rotate via:"
  echo "!!   aws iam delete-access-key --user-name $IAM_USER_NAME --access-key-id $ACCESS_KEY_ID"
fi

# ------------------------ 3. GCP Secret Manager ------------------------------
store_secret() { # store_secret <name> <file-or-"-">
  local name="$1" src="$2"
  if gcloud secrets describe "$name" >/dev/null 2>&1; then
    gcloud secrets versions add "$name" --data-file="$src"
    echo "Added new version to existing secret: $name"
  else
    gcloud secrets create "$name" --data-file="$src"
    echo "Created secret: $name"
  fi
}

step "Populating GCP Secret Manager (project $GCLOUD_PROJECT)"
if [[ "$SKIP_GCP_AWS_SECRETS" != true && -n "$ACCESS_KEY_ID" ]]; then
  AK_TMP=$(mktemp); SK_TMP=$(mktemp)
  printf '%s' "$ACCESS_KEY_ID" > "$AK_TMP"
  # Recover the freshly-created secret from the key file we just wrote
  SOURCE_SECRET=$(sed -n 's/^export AWS_SECRET_ACCESS_KEY=//p' "$KEY_FILE")
  printf '%s' "$SOURCE_SECRET" > "$SK_TMP"
  store_secret "aws-ses-access-key-id" "$AK_TMP"
  store_secret "aws-ses-secret-access-key" "$SK_TMP"
  shred -u "$AK_TMP" "$SK_TMP" 2>/dev/null || rm -f "$AK_TMP" "$SK_TMP"
fi

RECAPTCHA_SRC=$(mktemp)
if gcloud secrets describe "recaptcha-secret-key" >/dev/null 2>&1; then
  echo "Secret 'recaptcha-secret-key' already exists — leaving untouched."
else
  read -rsp "Enter reCAPTCHA v3 SECRET key (paste, Enter to confirm): " RECAPTCHA_INPUT
  echo
  [[ -n "$RECAPTCHA_INPUT" ]] || { echo "ERROR: reCAPTCHA secret is empty"; rm -f "$RECAPTCHA_SRC"; exit 1; }
  printf '%s' "$RECAPTCHA_INPUT" > "$RECAPTCHA_SRC"
  store_secret "recaptcha-secret-key" "$RECAPTCHA_SRC"
  shred -u "$RECAPTCHA_SRC" 2>/dev/null || rm -f "$RECAPTCHA_SRC"
fi

# -------------------- 4. app.yaml project substitution -----------------------
step "Substituting project ID in app.yaml"
if grep -q "YOUR_PROJECT_ID" "$APP_YAML"; then
  sed -i.bak "s/YOUR_PROJECT_ID/$GCLOUD_PROJECT/g" "$APP_YAML"
  rm -f "$APP_YAML.bak"
  echo "Replaced YOUR_PROJECT_ID with $GCLOUD_PROJECT in app.yaml."
else
  echo "app.yaml already has a concrete project ID — skipping."
fi

# ------------------------------- Summary -------------------------------------
step "Done!"
cat <<SUMMARY
Infrastructure ready. Remaining MANUAL steps:

  1. Click the SES verification link in $SENDER_EMAIL's inbox (if prompted).
  2. Put your reCAPTCHA v3 SITE key into:
       - index.html  (script tag query param)
       - js/main.js  (RECAPTCHA_SITE_KEY constant)
  3. Deploy:
       cd $PROJECT_ROOT
       gcloud app deploy
  4. Submit the form on the live site and watch:
       gcloud logging read --filter='resource:type="app_engine_runtime"' --freshness=10m

Cleanup reminders:
  - Delete infra/.secrets/aws_access_key.env after you've confirmed the
    deploy works (the secret lives safely in GCP Secret Manager).
  - Rotate the IAM access key annually:
      aws iam create-access-key --user-name $IAM_USER_NAME
      (then repeat sections 3-4 of this script)
SUMMARY
