#!/usr/bin/env python3
import paramiko
import time
import sys
import re

# ----------------------------------------------------------------------
# Edit these values before running:
# ----------------------------------------------------------------------
PANORAMA_HOST = "your.panorama.host"
USERNAME      = "your_username"
PASSWORD      = "your_password"
COMMAND_FILE  = "panorama.set"     # file containing all set commands
RETRY_LIMIT   = 3                  # max re-tries for failed lines
BASE_DELAY    = 0.05               # initial delay between commands (seconds)
SCALE_STEP    = 0.01               # extra delay added after each command
# ----------------------------------------------------------------------

def deploy_commands(host, user, passwd, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=passwd, look_for_keys=False)

    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999)  # clear banner

    print(f"Connected to {host}")

    # Enable scripting mode
    chan.send("set cli scripting-mode on\n")
    time.sleep(1)
    chan.recv(9999)

    delay = BASE_DELAY
    remaining = list(commands)

    for attempt in range(1, RETRY_LIMIT + 1):
        failed = []
        print(f"\nAttempt {attempt}: sending {len(remaining)} commands")

        for cmd in remaining:
            chan.send(cmd + "\n")
            time.sleep(delay)
            delay += SCALE_STEP          # gradually increase delay
        time.sleep(1)                     # give Panorama time to process
        output = chan.recv(65535).decode(errors="ignore")
        sys.stdout.write(output)
        sys.stdout.flush()

        # Look for errors to re-try
        for cmd in remaining:
            if re.search(rf"(Error|Invalid).*{re.escape(cmd.split()[0])}", output, re.IGNORECASE):
                failed.append(cmd)

        if not failed:
            print("\n All commands applied successfully.")
            break
        else:
            print(f"\n  {len(failed)} commands failed on attempt {attempt}.")
            if attempt < RETRY_LIMIT:
                print("Retrying in 5 seconds...")
                time.sleep(5)
                remaining = failed
            else:
                print("\n Some commands could not be applied after all retries:")
                for f in failed:
                    print("   ", f)

    chan.close()
    ssh.close()

def main():
    with open(COMMAND_FILE, "r", encoding="utf-8", errors="replace") as f:
        commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    deploy_commands(PANORAMA_HOST, USERNAME, PASSWORD, commands)

if __name__ == "__main__":
    main()
