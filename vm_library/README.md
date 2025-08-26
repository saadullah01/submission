

# VM Orchestrator for *CVE-GENIE*

Role: Provisions reproducible Ubuntu cloud images, configures dependencies, and runs experiments that attempt to reproduce CVEs inside isolated QEMU/KVM virtual machines.

---

## Requirements

* Host OS: Linux (tested on Ubuntu 22.04)
* CPU with virtualization support (Intel VT-x or AMD-V)
* Packages:

  ```bash
  sudo apt-get update
  sudo apt-get install -y qemu-kvm libvirt-daemon-system libvirt-clients \
                          bridge-utils virt-manager ansible python3-pip \
                          cloud-image-utils wget
  ```
* Permissions:

  ```bash
  sudo usermod -aG kvm,libvirt "$USER"
  newgrp kvm
  newgrp libvirt
  ```
* SSH key:

  ```bash
  chmod 0600 my-ssh-key
  ```

---

## Directory Overview

* `create-base.py` — Provisions the base VM image from the Ubuntu cloud image using QEMU + Ansible.
* `create-base.yml` — Ansible playbook to install dependencies (Python, Node.js, agent library).
* `create-seed.sh` — Generates a seed image (`my-seed.img`) with cloud-init configs (`userdata.yaml`, `metadata.yaml`).
* `qemu_utils.py` — Utilities for QEMU (image cloning, snapshotting, command builder).
* `ssh_utils.py` — Utilities for waiting on SSH and clean shutdown.
* `run_cve.py` — Runs a single CVE reproduction attempt inside a fresh VM overlay.
* `run_cve_with_snaps.py` — Same as above, but supports QEMU snapshots for multi-stage runs.
* `run_many_cves.py` — Batch runner for multiple CVEs.
* `experiment_runner.py` — Orchestrates end-to-end experiment batches (used in paper).
* `inventory.ini` — Ansible inventory template for VM access.
* `userdata.yaml`, `metadata.yaml` — Cloud-init configuration for initial VM setup.

---

## Setup Instructions

1. **Create seed image for cloud-init**

   ```bash
   ./create-seed.sh
   ```

2. **Provision base image**

   ```bash
   python3 create-base.py
   ```

   * Downloads the Ubuntu Jammy cloud image (if not cached).
   * Clones and resizes it to `images/base.img`.
   * Boots a VM, installs dependencies via Ansible, then shuts down.
   * Output: `images/base.img`.

3. **Verify SSH connectivity**
   Base image will accept SSH via:

   * User: `jammy`
   * Password: `jammy`
   * SSH key: `my-ssh-key`

---

## Running Experiments

### Single CVE run

```bash
python3 run_cve.py \
    -c CVE-2024-4340 \
    -j data/example/data.json \
    -m example-run \
    -t build,exploit,verify
```

Output and logs will be stored in `shared/<namespace>/<CVE>/`.

---

### Multiple CVEs

```bash
python3 run_many_cves.py \
    -i 0 \
    -m final-exp \
    -t build,exploit,verify \
    -s no \
    -d data/large_scale/data.json
```

This launches sequential CVE reproductions, automatically skipping completed ones.

---

## Notes

* **Snapshots:** Use `run_cve_with_snaps.py` if you want to checkpoint VM state (useful for multi-stage runs).
* **Shared directory:** Host and guest communicate via `/shared` (mounted inside VM). Logs and artifacts persist there.
* **Security:** All VMs are isolated QEMU instances with non-persistent overlays.
* **Cleaning up:** Overlay images are automatically removed if no exploit artifacts are generated.

---

## Expected Output

* For each CVE run:

  * `shared/<namespace>/<CVE>/log.txt` - Console logs from the AI agent.
  * `shared/<namespace>/<CVE>/scripts/` - Generated build/exploit scripts (if successful).
