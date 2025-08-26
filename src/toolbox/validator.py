import os, subprocess

class Validator:
    def __init__(self, verifier: str):
        self.verifier = verifier
        self.feedback = None

    def validate(self, timeout=180):
        cur_dir = os.getcwd()
        os.chdir("simulation_environments/" + os.environ['REPO_PATH'])

        # create verifier.py
        with open("verifier.py", "w") as f:
            f.write(self.verifier)

        # run verifier.py
        try:
            run = subprocess.run(["python3", "verifier.py"], capture_output=True, timeout=timeout)
            run_out = run.stdout.decode("utf-8")
            run_err = run.stderr.decode("utf-8")
        except subprocess.TimeoutExpired as e:
            run_out = e.stdout.decode("utf-8") if e.stdout else ""
            run_err = f"Process timed out after {timeout}s.\n" + (
                e.stderr.decode("utf-8") if e.stderr else ""
            )
        combined = f"🖥️ Verifier:\n-------------\n# STDOUT\n{run_out}\n\n# STDERR\n{run_err}"
        print(combined)

        os.chdir(cur_dir)

        if '3xploit66full' in run_out:
            return True,combined
        else:
            self.feedback = f"## VERIFIER SCRIPT\n```python\n{self.verifier}\n```\n\n## VERIFIER OUTPUT\n\n### STDOUT\n```\n{run_out}\n```\n\n### STDERR\n```\n{run_err}\n```"
            return False,combined