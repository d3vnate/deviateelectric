#!/usr/bin/env bash
# =============================================================================
# Deviate Electric — deploy with secrets resolved
#
# App Engine (standard) does not reliably expand Secret Manager references in
# `env_variables` at runtime (they arrive verbatim), so this script resolves
# the secrets, renders app.yaml with the ACTUAL values, deploys, and restores
# the original template. The rendered file exists only transiently and is
# restored on any exit path (incl. Ctrl-C). Secrets never enter git.
#
# Usage: ./infra/deploy.sh
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_APPYAML="$(mktemp)"
restore_original() {
  cp "$BACKUP_APPYAML" "$ROOT/app.yaml"
  rm -f "$BACKUP_APPYAML"
}
trap restore_original EXIT INT TERM
cp "$ROOT/app.yaml" "$BACKUP_APPYAML"

python3 - "$ROOT" <<'PY'
import pathlib, subprocess, sys

root = pathlib.Path(sys.argv[1])
template = (root / "app.yaml").read_text()

def secret_value(name: str) -> str:
    out = subprocess.run(
        ["gcloud", "secrets", "versions", "access", "latest", "--secret", name],
        capture_output=True, text=True, check=True,
    ).stdout.rstrip("\n")
    if not out:
        sys.exit(f"ERROR: secret '{name}' resolved to an empty value")
    return out

# Map each Secret Manager reference to its live value.
mapping = {
    "projects/deviate-electric/secrets/aws-ses-access-key-id/versions/latest":
        secret_value("aws-ses-access-key-id"),
    "projects/deviate-electric/secrets/aws-ses-secret-access-key/versions/latest":
        secret_value("aws-ses-secret-access-key"),
}

rendered = template
resolved = 0
for ref, value in mapping.items():
    if ref not in rendered:
        continue  # already substituted or removed
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    rendered = rendered.replace(ref, f'"{escaped}"')
    resolved += 1

(root / "app.yaml").write_text(rendered)
print(f"[deploy] rendered app.yaml with {resolved} secret(s) resolved (original stashed)")
PY

gcloud app deploy
# app.yaml is restored by the EXIT trap
