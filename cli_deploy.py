#!/usr/bin/env python3
import paramiko
import time
import sys

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
PANORAMA_HOST = "your.panorama.host"
USERNAME      = "your_username"
PASSWORD      = "your_password"
COMMAND_FILE  = "panorama.set"
DELAY_BETWEEN = 0.05          # seconds between commands
COMMIT_EVERY  = 5000          # commit and reconnect after this many commands
RETRY_DELAY   = 5             # wait 5 seconds after each commit before reconnect
# ----------------------------------------------------------------------

def connect_and_prepare():
    """Open a new SSH connection, enter configure & scripting mode, and return the channel & SSH client."""
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(PANORAMA_HOST, username=USERNAME, password=PASSWORD, look_for_keys=False)

    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999)  # clear banner

    # Enter configure mode
    chan.send("configure\n")
    time.sleep(1)
    chan.recv(9999)

    # Enable scripting mode
    chan.send("set cli scripting-mode on\n")
    time.sleep(1)
    chan.recv(9999)

    return ssh, chan

def commit_config(chan):
    """Send a commit command and monitor until commit finishes."""
    print("\n*** Performing commit ***")
    chan.send("commit\n")
    time.sleep(30)

def deploy_commands(commands):
    ssh, chan = connect_and_prepare()
    total = len(commands)

    sent_count = 0
    for idx, cmd in enumerate(commands, start=1):
        chan.send(cmd + "\n")
        sent_count += 1
        print(f"[{idx}/{total}] Sent: {cmd}")
        time.sleep(DELAY_BETWEEN)

        if sent_count == COMMIT_EVERY and idx != total:
            # Commit, wait, disconnect, and reconnect
            commit_config(chan)
            print(f"Waiting {RETRY_DELAY} seconds before reconnecting...")
            time.sleep(RETRY_DELAY)
            chan.close()
            ssh.close()
            print("Reconnecting to Panorama...")
            ssh, chan = connect_and_prepare()
            sent_count = 0  # reset counter for next batch

    print("\nAll configuration commands have been sent.")
    print("Performing final commit...")
    commit_config(chan)

    chan.close()
    ssh.close()
    print("Session closed.")

def main():
    with open(COMMAND_FILE, "r", encoding="utf-8", errors="replace") as f:
        commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    deploy_commands(commands)

if __name__ == "__main__":
    main()


if __name__ == "__main__":
    main()
