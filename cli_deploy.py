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
COMMAND_FILE  = "panorama.set"     # file with all set commands
DELAY_BETWEEN = 0.05              # fixed delay in seconds between commands
# ----------------------------------------------------------------------

def deploy_commands(host, user, passwd, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=passwd, look_for_keys=False)

    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999)  # clear initial banner

    print(f"Connected to {host}")

    # ------------------------------------------------------------------
    # Enter configure mode
    # ------------------------------------------------------------------
    print("Entering configure mode...")
    chan.send("configure\n")
    time.sleep(1)
    chan.recv(9999)

    # Enable scripting mode (inside configure context)
    print("Enabling scripting mode...")
    chan.send("set cli scripting-mode on\n")
    time.sleep(1)
    chan.recv(9999)

    total = len(commands)
    for idx, cmd in enumerate(commands, start=1):
        chan.send(cmd + "\n")
        print(f"[{idx}/{total}] Sent: {cmd}")
        time.sleep(DELAY_BETWEEN)

    print("All configuration commands have been sent.")

    # ------------------------------------------------------------------
    # Final commit
    # ------------------------------------------------------------------
    print("Committing configuration to Panorama...")
    chan.send("commit\n")
    time.sleep(1)

    # Monitor commit progress
    while True:
        time.sleep(5)
        if chan.recv_ready():
            output = chan.recv(65535).decode(errors="ignore")
            sys.stdout.write(output)
            sys.stdout.flush()
            # Heuristic: detect completion text
            if ("Configuration committed successfully" in output
                or "Commit succeeded" in output
                or "commit complete" in output.lower()):
                print("\nCommit completed.")
                break

    chan.close()
    ssh.close()
    print("Session closed.")

def main():
    with open(COMMAND_FILE, "r", encoding="utf-8", errors="replace") as f:
        commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    deploy_commands(PANORAMA_HOST, USERNAME, PASSWORD, commands)

if __name__ == "__main__":
    main()

