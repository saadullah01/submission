#!/usr/bin/env python3
import subprocess
import time
import os
import shutil
import argparse

from ssh_utils import wait_for_ssh, shutdown
from qemu_utils import create_overlay, get_qemu_cmd

def main():
    parser = argparse.ArgumentParser(
        description="Run CVE-Genie"
    )
    parser.add_argument("-c", "--cve", required=True,
                        help="The CVE ID to run")
    parser.add_argument("-j", "--json", required=True,
                        help="The CVE JSON cache to run")
    parser.add_argument("-m", "--model", required=True,
                        help="The model to use")
    parser.add_argument("-n", "--namespace", default="default",
                        help="The namespace for the VM")
    parser.add_argument("-p", "--port", type=int, default=2222,
                        help="The SSH port for the VM")
    parser.add_argument("-t", "--type", required=False, 
                        help="The type of run: build, exploit, verify")
    parser.add_argument("-ak", "--anthropic_key", required=False, type=str, default=None,
                        help="Anthropic API key if using Anthropic models")
    args = parser.parse_args()
    
    cve = args.cve
    model = args.model
    namespace = args.namespace
    ssh_port = args.port
    cve_json = args.json
    run_type = args.type
    
    input_image = os.path.dirname(os.path.abspath(__file__))+"/images/base.img"
    cpus = 2
    memory = 8192
    ssh_user = "jammy"
    ssh_key = "my-ssh-key"
    playbook = "run-cve.yml" 
    shared_dir = os.path.dirname(os.path.abspath(__file__))+f"/shared/{namespace}"
    inv_path = f"{shared_dir}/inventory.ini"
    output_image = f"{shared_dir}/{cve}.img"
    
    # Create the shared dir to capture output
    os.makedirs(shared_dir, exist_ok=True)
    
    # Setup env for the run
    shutil.copyfile(os.path.dirname(os.path.abspath(__file__))+"/../src/.env",f"{shared_dir}/.env")
    with open(f"{shared_dir}/.env",'a') as f:
        print(f'\nANTHROPIC_API_KEY=\"{args.anthropic_key}\"', file=f)
        print(f'\nMODEL=\"{model}\"', file=f)
    
    shutil.copyfile("inventory.ini",f"{inv_path}")
    subprocess.run(["sed", "-i", "s/2222/"+str(ssh_port)+"/g", inv_path])
    
    # 1) Copy the base image
    create_overlay(input_image, output_image)

    # 2) Launch QEMU/KVM
    qemu_cmd = get_qemu_cmd(cpus, memory, output_image, ssh_port, shared_dir, init=False)
    
    print(f"Starting VM with QEMU...\n{' '.join(qemu_cmd)}")
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
    print(f"Running Ansible playbook {playbook} for cve {cve} in {cve_json}")
    subprocess.run([
        "ansible-playbook", "-i", inv_path, "--extra-vars", f'test_case=\'{cve}\'', "--extra-vars", f'cve_json=\'{cve_json}\'', "--extra-vars", f'run_type=\'{run_type}\'',
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
        
    print(f"✅ CVE run complete")
    
    # 6) Clean up
    if not os.path.exists(f'{shared_dir}/{cve}/scripts/'):
        os.remove(output_image)

if __name__ == "__main__":
    main()
