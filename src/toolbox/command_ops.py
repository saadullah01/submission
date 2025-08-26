import subprocess
import os
import time
import uuid
import signal

from agentlib.lib import tools

@tools.tool
def execute_find_command(filename: str) -> str:
    """
    This tool runs a 'find' command in the given directory to search for a specific file.
    If no files match, it returns "No files found."
    :param filename: The filename (or part of it) to search for.
    :return: The output of the 'find' command or a message if no files are found.
    """
    
    cur_dir = os.getcwd()
    os.chdir("simulation_environments/" + os.environ['REPO_PATH'])
    # Execute the find command
    process = subprocess.run(
        f"find ./ -type f -name '*{filename}*'",
        shell=True,
        capture_output=True,
        text=True,
        timeout=10
    )
    os.chdir(cur_dir)
    
    # Check if files are found
    if process.stdout.strip():
        return f"# Files found:\n{process.stdout}"
    else:
        return "No files found."

@tools.tool
def execute_ls_command(dir: str) -> str:
    """
    This tool runs an ls command in the given directory and returns the output.
    :param dir: The directory to run the ls command in.
    :return: The output of the ls command.
    """

    # print("Trying to execute: ls on", dir, "\nProceed? y/N")
    # p = input()
    # if p!='y':
    #     return "Unable to execute, permission denied"
    
    return execute_command_foreground(f"ls -a {dir}")

# Environment variables for commands
env = {}

@tools.tool
def set_environment_variable(key: str, value: str, clear: bool) -> str:
    """
    This tool sets an environment variable that will be used by all successive commands.

    :param key: The environment variable name.
    :param value: The value to assign to the environment variable.
    :param clear: Clears all previous env variables set using this command.
    :return: Confirmation message.
    """
    
    global env

    # Check for confirmation
    # print(f"Trying to export {key}={value}, clear={clear}. \nProceed? y/N")
    # p = input()
    # if p.lower() != 'y':
    #     return "Operation cancelled by user."

    if clear:
        env = {}
    env[key] = value
    
    return f"Success, current env_list={env}."

@tools.tool
def execute_linux_command(command: str, background: bool) -> str:
    """
    This tool runs a command (in the root directory of the target repository) in the shell.
    export commands will not work independently.
    Make sure not run commands that will ask for user input as they will hang indefinitely.
    sudo commands will work.

    :param command: The command to run.
    :param background: If the command should be run in background.
    :return: The output of the command.
    """
    print("Trying to execute: ", command)
    if background:
        return execute_command_background(command)
    else:
        return execute_command_foreground(command)

def execute_command_foreground(command: str) -> str:
    """
    This tool runs a command (in the root directory of the target repository) in the shell, waits for termination and returns the output.
    Do not spawn processes that run servers as it will hang indefinitely.

    :param command: The command to run.
    :return: The output of the command.
    """
    
    # print("Trying to execute: ", command, "\nProceed? y/N")
    # p = input()
    # if p!='y':
    #     return "Unable to execute, permission denied"
    
    stdout_log = create_unique_logfile("stdout")
    stderr_log = create_unique_logfile("stderr")
    try:
        with open(stdout_log, "w") as stdout, open(stderr_log, "w") as stderr:
            subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                cwd="simulation_environments/" + os.environ["REPO_PATH"],
                stdout=stdout,
                stderr=stderr,
                text=True,
                timeout=300,
                errors="ignore",
                env=os.environ.copy() | env
            )
    except subprocess.TimeoutExpired:
        return "Timed out! If this command starts a server/anything that expects input, try using execute_command_background"

    # Get the last 100 lines of both log files
    return get_tail_log(stdout_log, stderr_log)

background_process_list={}

def execute_command_background(command: str) -> str:
    """
    This tool runs a command in the background (in the root directory of the target repository) in the shell and returns the output.
    Use this to start servers.
    Do not spawn processes using single &.

    :param command: The command to run.
    :return: The output of the command.
    """
    
    global background_process_list

    command = command.removesuffix('&')
    # print("Trying to execute: ", command, "\nProceed? y/N")
    # p = input()
    # if p!='y':
    #     return "Unable to execute, permission denied"
    
    stdout_log = create_unique_logfile("stdout")
    stderr_log = create_unique_logfile("stderr")

    process = subprocess.Popen(
        command,
        shell=True,
        executable="/bin/bash",
        cwd="simulation_environments/" + os.environ["REPO_PATH"],
        stdout=open(stdout_log, "w"),
        stderr=open(stderr_log, "w"),
        preexec_fn=os.setsid,
        env=os.environ.copy() | env
    )

    background_process_list[process.pid]=process

    time.sleep(5)

    # Get the last 100 lines of both log files
    return get_tail_log(stdout_log, stderr_log)

def cleanup_background_processes():
    global background_process_list
    global env

    env={}

    for pid in list(background_process_list.keys()):
        try:
            # Kill the entire process group
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            print(f"Terminated process group for PID {pid}")
        except:
            # print(f"Process group for PID {pid} not found (already terminated?)")
            pass
        finally:
            # Remove from the list
            del background_process_list[pid]

def create_unique_logfile(suffix: str) -> str:
    """Generate a unique log file in /tmp with a specific suffix."""
    log_filename = f"/tmp/{uuid.uuid4().hex[:5]}_{suffix}.log"
    return log_filename

def get_last_lines(file_path: str, line_count: int = 100):
    """Retrieve the last `line_count` lines from a file."""
    try:
        with open(file_path, "r") as file:
            r=file.readlines()
            return "".join(r[-line_count:]), len(r)
    except Exception as e:
        return f"Error reading log file: {e}"
    
def get_tail_log(stdout_log: str, stderr_log: str):
    last_stdout_lines, stdout_len = get_last_lines(stdout_log, 100)
    last_stderr_lines, stderr_len = get_last_lines(stderr_log, 100)
    return (
        f"LOGS for current command\n"
        f"STDOUT Log File: {stdout_log}\nLast {min(100, stdout_len)} lines out of {stdout_len}:\n{last_stdout_lines}\n\n"
        f"STDERR Log File: {stderr_log}\nLast {min(100, stderr_len)} lines out of {stderr_len}:\n{last_stderr_lines}\n"
    )
    
# @tools.tool
# def get_background_command_logs(pid: int) -> str:
#     """
#     This tool captures any pending logs from a background process's stdout and stderr.

#     :param pid: The pid of the target process.
#     :return: String with the outputs from the process.
#     """
#     print("Trying to get logs for PID: ", pid, "\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
#     return capture_outputs(pid, 0)

# def read_from_stream(stream):
#     read = b""
#     while True:
#         data = stream.read(1)
#         if not data:
#             break
#         read += data
#     read = read.decode(errors='ignore')
#     return read

# def capture_outputs(pid: int, timeout: int):
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"
    
#     p = Ps[pid]
#     reads = [p.stdout.fileno(), p.stderr.fileno()]
#     ret = select.select(reads, [], [], timeout)
#     out = f"Output for process with PID: {pid}\n"
#     for fd in ret[0]:
#         if fd == p.stdout.fileno():
#             read = read_from_stream(p.stdout)
#             out+=('stdout:\n' + read + '\n')
#         if fd == p.stderr.fileno():
#             read = read_from_stream(p.stderr)
#             out+=('stderr:\n' + read + '\n')
#         out += "###\n"
#     if not ret[0]:
#         out += "No new output on stdout/stderr\n"
#     if p.poll() is None:
#         out += "status: Process is still running, you can consider waiting.\n"
#     else:
#         out += f"status: Process exited with code {p.returncode}\n"
#         del Ps[pid]
#     return out

# @tools.tool
# def send_inputs(pid: int, inp: str) -> str:
#     """
#     This tool sends an input to the stdin of the given pid if it is still running.

#     :param pid: The pid of the target process.
#     :param inp: The input to send via stdin.
#     :return: String denoting if the write was succesful or not.
#     """

#     print(f"Trying to write {inp} to {pid}...\nProceed? y/N")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"
    
#     pid = int(pid)
#     if pid not in Ps:
#         return "Process not found, PID: " + str(pid) + "\n"
#     p = Ps[pid]
#     p.stdin.write(str.encode(inp))
#     p.stdin.flush()
#     return f"###Write to stdin of PID {pid} finished###\n"

# @tools.tool
# def wait(tim: int) -> str:
#     """
#     This tool waits for the given duration in seconds.
#     Can be used when you are waiting for subsequent outputs from a process.
#     Will display outputs from all running processes after the wait.

#     :param tim: Duration in seconds.
#     :return: If wait was successful.
#     """

#     print("Trying to sleep for: ", tim, "\nProceed?")
#     p = input()
#     if p!='y':
#         return "Unable to execute, permission denied"

#     time.sleep(tim)
#     outs = ""
#     for pid in list(Ps.keys()):
#         outs += capture_outputs(pid)

#     return outs