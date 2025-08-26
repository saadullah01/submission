import shutil
import subprocess
import socket
import time
import select

def get_qemu_cmd(cpus: int, memory: int, img: str, ssh_port: int, shared_dir: str = None, init: bool = True, snapshot_name = None):
    qemu_cmd = [
        "qemu-system-x86_64",
        "-machine", "q35,accel=kvm",
        "-cpu", "host",
        "-smp", str(cpus),
        "-m", str(memory),
        "-drive", f"file={img},if=virtio,format=qcow2,cache=none,aio=threads",
        "-netdev", f"user,id=net0,hostfwd=tcp::{ssh_port}-:22",
        "-monitor", f"unix:/tmp/qemu-monitor-socket-{ssh_port},server,nowait",
        "-device", "virtio-net-pci,netdev=net0",
        "-nographic"
    ]
    
    if snapshot_name:
        qemu_cmd.extend(["-loadvm", snapshot_name])
    
    if shared_dir:
        qemu_cmd.extend(["-virtfs", f"local,id=hostshare,path={shared_dir},security_model=mapped,mount_tag=hostshare"])
    
    if init:
        qemu_cmd.extend(["-drive", f"if=virtio,format=raw,file=my-seed.img"])
    
    return qemu_cmd

def savevm_snapshot(sock_path, snapshot_name="snap1", timeout=60):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)

        # Clear initial banner or residual messages
        time.sleep(0.2)
        while True:
            rlist, _, _ = select.select([s], [], [], 0.1)
            if rlist:
                _ = s.recv(4096)
            else:
                break

        s.sendall(f"savevm {snapshot_name}\n".encode())

        response = b""
        end_time = time.time() + timeout

        while time.time() < end_time:
            rlist, _, _ = select.select([s], [], [], 0.5)
            if rlist:
                chunk = s.recv(4096)
                response += chunk
                if b"Error" in response:
                    break
            else:
                break  # no more data; likely success

        response_text = response.decode(errors="ignore")
        if "Error" in response_text:
            raise RuntimeError(f"[-] Failed to save snapshot: {response_text.strip()}")
        else:
            print(f"[+] Snapshot '{snapshot_name}' saved successfully (no error returned).")


def clone_and_resize_image(input_image: str,
                           output_image: str,
                           extra_size: str = "+50G") -> None:
    """
    Copy input_image → output_image and then resize it by extra_size
    (e.g. '+10G' to add 10 GiB).
    """
    # 1) Copy the file
    shutil.copyfile(input_image, output_image)
    print(f"Copied {input_image} → {output_image}")

    # 2) Resize with qemu-img
    subprocess.run(
        ["qemu-img", "resize", output_image, extra_size],
        check=True
    )
    print(f"Resized {output_image} by {extra_size}")
    
def create_overlay(input_image: str,
                    output_image: str) -> None:

    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", f"{input_image}", f"{output_image}"],
        check=True
    )
    print(f"Created new overlay {output_image} backed by {input_image}")
    
if __name__ == "__main__":
    create_overlay("base.img", "cve-101.img")