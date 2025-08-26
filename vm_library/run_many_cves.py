import subprocess
import json
import os.path
import argparse
import time

if __name__== "__main__":
    parser = argparse.ArgumentParser(
        description="Run CVE-Genie"
    )
    parser.add_argument("-i", "--index", required=False, type=int, default=0,
                        help="The machine index")
    parser.add_argument("-m", "--model", required=True,
                        help="The model to use")
    parser.add_argument("-t", "--type", required=True, choices=['build', 'exploit', 'verify', 'build,exploit', 'exploit,verify', 'build,exploit,verify'],
                        help="The type of run: build, exploit, verify")
    parser.add_argument("-s", "--snap", required=True, choices=['yes', 'no'],
                        help="Whether to use snapshots")
    parser.add_argument("-d", "--data", required=True, type=str,
                        help="Path to the CVE data file")
    args = parser.parse_args()

    cves=[]
    # Change
    json_path = f"../src/{args.data}"
    print(f"Loading CVE data from {json_path}")
    cve_data = json.loads(open(json_path).read())
    cves = cve_data.keys()
    script_name = "run_cve.py" if args.snap == 'no' else "run_cve_with_snaps.py"
    
    if not os.path.exists(os.path.dirname(os.path.abspath(__file__))+f"/images/base.img"):
        print("Create base first!")
        exit(1)

    for cve in cves:
        print("Running cve", cve)
        
        if os.path.exists(os.path.dirname(os.path.abspath(__file__))+f"/shared/{args.model}-machine{str(args.index)}/{cve}"):
            continue
        
        out = subprocess.run(["python3", "-u", f"{script_name}",
                        "-c", cve,
                        # Change
                        "-j", f"./{args.data}",
                        "-m", args.model,
                        "-p", str(2222+args.index),
                        # Change
                        "-n", f"{args.model}-machine{str(args.index)}",
                        # Change
                        "-t", args.type])
        if out.returncode:
            print(f"{cve} crashed, exiting...")
            subprocess.run("kill $(ps -aux | grep qemu | grep "+str(2222+args.index)+"-:22 | awk '{print $2}')", shell=True)
            time.sleep(5)
            # Change
            subprocess.run("rm "+os.path.dirname(os.path.abspath(__file__))+f"/shared/{args.model}-machine{str(args.index)}/{cve}.img", shell=True)
