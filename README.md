# CVE-Genie

An LLM-based multi-agent framework for end-to-end reproduction of CVEs.

See end-to-end reproduction logs and outputs of CVE-2024-4340 [here](src/results/CVE-2024-4340) and Figure 2 in the paper.

# 🏃‍♂️ How to Run 
## a) In DevContainer
> ‼️ Easy to setup but it might not be compatible for CVEs that require running multiple services, as it can crash the DevContainer
1. Clone this repository and `cd` into it.
2. Start the `devcontainer` in VS Code
3. `cd` into the `src` directory
4. Create `.env` file in `src`, and add the `OPENAI_API_KEY` to use
5. Run the following command to reproduce given CVE (e.g., CVE-2024-4340)
   ```
   ENV_PATH=.env MODEL=example_run python3 main.py --cve CVE-2024-4340 --cache data/example/data.json --build,exploit,verify
   ```
6. The final results will be stored in `shared/CVE-2024-4340/`

## b) In a Virtual Machine
Read the [VM Library Documentation](vm_library/README.md) on how to run it in a VM.