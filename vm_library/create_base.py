#!/usr/bin/env python3
import subprocess
import time
import os

from ssh_utils import wait_for_ssh, shutdown
from qemu_utils import clone_and_resize_image, get_qemu_cmd

def main():
    input_image = os.path.dirname(os.path.abspath(__file__))+"/images/jammy-server-cloudimg-amd64.img"
    output_image = os.path.dirname(os.path.abspath(__file__))+"/images/base.img"
    cpus = 2
    memory = 8192
    ssh_port = 2222
    ssh_user = "jammy"
    ssh_key = "my-ssh-key"
    playbook = "create-base.yml" 
    inv_path = "inventory.ini"
    
    if not os.path.exists(input_image):
        print("Downloading Ubuntu cloud image")
        subprocess.run(["wget", 
                        "-O", input_image,
                        "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"])
    
    # 1) Copy the base image
    clone_and_resize_image(input_image, output_image)

    # 2) Launch QEMU/KVM
    qemu_cmd = get_qemu_cmd(cpus, memory, output_image, ssh_port)
    
    print("Starting VM with QEMU...")
    qemu_proc = subprocess.Popen(
        qemu_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL
    )

    # 3) Wait for SSH availability
    print(f"Waiting for SSH on 127.0.0.1:{ssh_port}...")
    
    wait_for_ssh("127.0.0.1", ssh_port, ssh_user, ssh_key)

    # 4) Run the Ansible playbook
    print(f"Running Ansible playbook {playbook}…")
    subprocess.run([
        "ansible-playbook", "-i", inv_path,
        playbook
    ], check=True)

    # 5) Clean shutdown of the VM
    print("Shutting down the VM gracefully...")
    shutdown("127.0.0.1", ssh_port, ssh_user, ssh_key)
    
    try:
        while True:
            time.sleep(1)
            if qemu_proc.poll() is not None:
                print("QEMU exited!")
                break
    except KeyboardInterrupt:
        print("Shutting down QEMU…")
        qemu_proc.terminate()
        qemu_proc.wait()
        
    print(f"✅ Provisioned image ready at: {output_image}")

if __name__ == "__main__":
    main()
