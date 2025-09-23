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
DELAY_BETWEEN = 0.15          # seconds between commands
COMMIT_EVERY  = 5000          # commit after this many commands
CHECK_INTERVAL = 60           # check connection every 60 seconds
# ----------------------------------------------------------------------

def ensure_connection(chan):
    """
    Check that the SSH channel is alive. If not, raise an exception.
    """
    if chan.closed or not chan.active:
        raise Exception("SSH channel closed unexpectedly.")

def commit_config(chan):
    """
    Send a commit command and monitor output until completion.
    """
    print("\n*** Performing commit ***")
    chan.send("commit\n")
    time.sleep(1)
    while True:
        time.sleep(30)
        if chan.recv_ready():
            output = chan.recv(65535).decode(errors="ignore")
            sys.stdout.write(output)
            sys.stdout.flush()
            if ("Configuration committed successfully" in output or
                "Commit succeeded" in output or
                "commit complete" in output.lower()):
                print("\n*** Commit completed ***\n")
                break

def deploy_commands(host, user, passwd, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=user, password=passwd, look_for_keys=False)

    chan = ssh.invoke_shell()
    time.sleep(1)
    chan.recv(9999)  # clear banner

    print(f"Connected to {host}")

    # Enter configure mode
    chan.send("configure\n")
    time.sleep(1)
    chan.recv(9999)

    # Enable scripting mode
    chan.send("set cli scripting-mode on\n")
    time.sleep(1)
    chan.recv(9999)

    total = len(commands)
    last_check = time.time()

    for idx, cmd in enumerate(commands, start=1):
        # Health check every CHECK_INTERVAL seconds
        if time.time() - last_check > CHECK_INTERVAL:
            print("\n[Health Check] Verifying SSH connection...")
            ensure_connection(chan)
            last_check = time.time()
            print("[Health Check] Connection is active.")

        chan.send(cmd + "\n")
        print(f"[{idx}/{total}] Sent: {cmd}")
        time.sleep(DELAY_BETWEEN)

        # Periodic commit every COMMIT_EVERY commands
        if idx % COMMIT_EVERY == 0:
            commit_config(chan)

    print("\nAll configuration commands have been sent.")
    print("Performing final commit...")
    commit_config(chan)

    chan.close()
    ssh.close()
    print("Session closed.")

def main():
    with open(COMMAND_FILE, "r", encoding="utf-8", errors="replace") as f:
        commands = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    deploy_commands(PANORAMA_HOST, USERNAME, PASSWORD, commands)

if __name__ == "__main__":
    main()
