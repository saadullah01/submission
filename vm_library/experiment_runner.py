import subprocess
import os

if not os.path.exists(os.path.dirname(os.path.abspath(__file__))+f"/images/base.img"):
    print("Creating base image")
    subprocess.run(["python3", "-u", "create_base.py"])

MODEL = "example_run"

START = 1
NUM_EXP = 1

TYPE = "build,exploit,verify"

SNAP = "no"

DATA = f"data/example/data.json"

for i in range(START,START+NUM_EXP):
    cmd = (
        f"nohup python3 -u run_many_cves.py "
        f"-i {i} -m {MODEL} -t {TYPE} -s {SNAP} -d {DATA} "
        f"> nohup{i}.out 2>&1 &"
    )
    subprocess.Popen(cmd, shell=True)
