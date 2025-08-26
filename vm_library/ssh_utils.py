#!/usr/bin/env python3
import socket
import subprocess
import time

def shutdown(host, port, user, key_path):
    """
    Ask the remote VM to shut down.  
    If SSH dies with returncode 255 (expected when the host goes down),
    we swallow it; otherwise we re-raise.
    """
    cmd = [
        "ssh",
        "-p", str(port),
        "-i", key_path,
        "-o", "StrictHostKeyChecking=no",
        f"{user}@{host}",
        "sudo poweroff -f"
    ]

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        # 255 = SSH connection error (host went away)
        if e.returncode == 255:
            print("Shutdown command sent; remote host closed the connection as expected.")
            return
        # some *other* error — re-raise so you notice it
        raise

def wait_for_ssh(host, port, user, key_path, retry_interval=5, timeout=10):
    """
    Loop until the SSH command succeeds:
      1) quick TCP port check
      2) ssh -oBatchMode=yes -oStrictHostKeyChecking=no -i key ...
    """
    print(f"Waiting for SSH on {user}@{host}:{port} using key {key_path}...")
    ssh_cmd = [
        "ssh",
        "-i", key_path,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={timeout}",
        "-p", str(port),
        f"{user}@{host}",
        "true",
    ]

    while True:
        # 1) port alive check
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
        except socket.error:
            ts = time.strftime('%H:%M:%S')
            print(f"[{ts}] Port {port} not open yet. Retrying in {retry_interval}s...")
            time.sleep(retry_interval)
            continue

        # 2) try ssh
        ts = time.strftime('%H:%M:%S')
        proc = subprocess.run(
            ssh_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        if proc.returncode == 0:
            print(f"[{ts}] SSH connection established!")
            return
        else:
            print(f"[{ts}] SSH not ready yet (exit code {proc.returncode}). Retrying in {retry_interval}s...")
            time.sleep(retry_interval)
            
if __name__ == "__main__":
    # wait_for_ssh("127.0.0.1", 2222, "jammy", "my-ssh-key", 10)
    shutdown("127.0.0.1", 2222, "jammy", "my-ssh-key")
