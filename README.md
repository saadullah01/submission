# CVE-Genie

# 🏃‍♂️ How to Run 
## a) In DevContainer
> ‼️ Easy to setup but it might not be compatible for CVEs that require running multiple services, as it can crash the DevContainer
1. Clone this repository
   ```
   git clone https://github.com/saadullah01/cve-genie.git
   cd cve-genie
   ```
2. Start the `devcontainer` in VS Code
3. `cd` into the `src` directory
4. Create `.env` file in `src`, and add the `OPENAI_API_KEY` to use
5. Run the following command to reproduce given CVE (e.g., CVE-2024-4340)
   ```
   ENV_PATH=.env MODEL=example_run python3 main.py --cve CVE-2024-4340 --cache data/final/2024_cves_final/ --build --exploit
   ```
6. The final results will be stored in `shared/CVE-2024-4340/`

## b) In a Virtual Machine
Read the [VM Library Documentation](vm_library/README.md) on how to run it in a VM.