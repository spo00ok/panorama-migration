#!/usr/bin/env bash
#
# Deploy Panorama set commands via SSH with scaling delay and retries.

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
HOST="your.panorama.host"
USER="your_username"
PASS="your_password"          # optional if using key auth; see note below
COMMAND_FILE="panorama.set"   # file containing set commands
RETRY_LIMIT=3                 # number of times to retry failed commands
BASE_DELAY=0.05               # initial delay (seconds) between commands
SCALE_STEP=0.01               # increment to delay after each command
# ----------------------------------------------------------------------

# If possible, use SSH keys and ssh-agent instead of storing a password.
# For password auth with OpenSSH you can use sshpass (install separately)
# and replace "ssh" below with "sshpass -p $PASS ssh".

if [[ ! -f "$COMMAND_FILE" ]]; then
  echo "Command file '$COMMAND_FILE' not found."
  exit 1
fi

# Function to send a single command and capture the output
send_command() {
  local cmd="$1"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no "$USER@$HOST" "$cmd" 2>&1
}

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
commands=()
while IFS= read -r line; do
  [[ -z "$line" || "$line" =~ ^# ]] && continue
  commands+=("$line")
done < "$COMMAND_FILE"

attempt=1
remaining=("${commands[@]}")

while (( attempt <= RETRY_LIMIT )); do
  echo
  echo "Attempt $attempt: sending ${#remaining[@]} commands"
  delay=$BASE_DELAY
  failed=()

  for cmd in "${remaining[@]}"; do
    echo "Sending: $cmd"
    output=$(send_command "$cmd")
    echo "$output"

    # Look for common Panorama error indicators
    if grep -qiE "error|invalid" <<< "$output"; then
      echo "Error detected for command: $cmd"
      failed+=("$cmd")
    fi

    # Gradually increase delay between commands
    sleep "$delay"
    delay=$(awk -v d="$delay" -v s="$SCALE_STEP" 'BEGIN{printf "%.2f", d + s}')
  done

  if (( ${#failed[@]} == 0 )); then
    echo "All commands applied successfully."
    exit 0
  fi

  if (( attempt < RETRY_LIMIT )); then
    echo "${#failed[@]} commands failed. Retrying in 5 seconds..."
    sleep 5
    remaining=("${failed[@]}")
    ((attempt++))
  else
    echo "Some commands could not be applied after $RETRY_LIMIT attempts:"
    for f in "${failed[@]}"; do
      echo "   $f"
    done
    exit 2
  fi
done
