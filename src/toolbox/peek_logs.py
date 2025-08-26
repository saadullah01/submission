
import os
import subprocess

from agentlib.lib import tools

@tools.tool
def search_string_in_file(file_path: str, needle: str) -> str:
    """
    Search for a specific string in all files within the project.
    This tool can be used to search for specific variables names, types or functions etc...
    The needle MUST be a string with length greater than 3.
    The output format is <file_path>:<line_number>:<line_content>
    
    :param file_path: The path of the log file to search in. The valid log paths have been provided to you.
    :param needle: The string to search for.
    :return: A list of files containing the string and one line code that shows
             how the needle is used, or an error message if not found.
    """

    # Execute the ag command to search for the needle in the project folder
    if len(needle) < 4:
        return "The needle must be a string with length greater than 3 and less than 10."

    # Check if the file exists
    if not os.path.exists(file_path):
        return f"File {file_path} does not exist"

    search_result = []
    result = subprocess.run(['grep', "-n", str(file_path), needle], capture_output=True, text=True)
    result = result.stdout.splitlines()
    res_idx = 1
    for line in result[:10]:
        if line:
            search_result.append(f" Match {res_idx}: {line}")
            res_idx+=1
    
    if len(search_result) == 0:
        return f"No occurence of {needle} found in the log file."
    else:
        search_result_report = ""
        search_result_report += f"Found {len(search_result)} occurences of {needle} in the log file:\n"
        for line in search_result:
            search_result_report += f"{line}\n"

        return search_result_report
    