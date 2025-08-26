import json, os, subprocess
from data.scripts import cve_processor, scraper_utils

class CVEDataProcessor:
    def __init__(self, cve_id: str, cve_json: str = None):
        self.cve_id = cve_id
        self.cve_json = cve_json

    def knowledge_builder_setup(cve_path: str) -> dict:
        """
        Loads the cve json file from the given path
        """
        if not os.path.exists(cve_path):
            raise FileNotFoundError(f"❌ File not found at {cve_path}")
        return json.loads(open(cve_path, "r").read())

    def pre_reqs_builder_setup(cve_info: dict) -> str:
        """
        Clones a repo to a the parent of given commit and returns the directory tree of the repo
        """
        cur_dir = os.getcwd()
        os.chdir("simulation_environments/")

        if not os.path.exists(cve_info["project"]):
            subprocess.run(f"git clone {cve_info['git_url']}.git", shell=True, timeout=300)
            os.chdir(cve_info["project"])
            subprocess.run(f"git checkout {cve_info['hash']}~1", shell=True, timeout=300)
        else:
            os.chdir(cve_info["project"])
        os.environ['REPO_PATH'] = f"{cve_info['project']}/"
        dir_tree = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        os.chdir(cur_dir)

        return dir_tree
    
    def run(self, code_url: str = "") -> dict:
        cur_dir = os.getcwd()
        # 1) If cache exists, load cve from cache
        if self.cve_json:
            if os.path.exists(self.cve_json):
                cve = json.loads(open(self.cve_json, "r").read()).get(self.cve_id)
                if not cve:
                    raise ValueError(f"❌ {self.cve_id} not found in cache file")
            else:
                raise FileNotFoundError(f"❌ {self.cve_id} cache file not found at {self.cve_json}")
        
        # 2) Load and process cve from the 'cvelist' repository
        else:
            # a) get raw cve json from the cvelist repo
            _cve = cve_processor.get_cve_by_id(self.cve_id)

            # b) get github url from patch commit
            patch_urls = _cve.get("patch_urls")
            if patch_urls:
                print(f"🔍 Found patch URLs: {patch_urls}")

                version_data = _cve.get("version_data")
                if version_data:
                    try:
                        version = cve_processor.get_software_versions(_cve['id'])[0]
                    except Exception as e:
                        version = (False, 'anomaly')
                    
                    if version[1] != 'n/a' and version[1] != 'anomaly':
                        tag = cve_processor.affected_version_exist(patch_urls[0]['owner'], patch_urls[0]['project'], version[1], version[0])
                    
                    if tag:
                        cve = {
                            "published_date": cve_processor.get_published_date(_cve['id']),
                            "patch_commits": [
                                {
                                    "url": patch['patch_commit_url'],
                                    "content": cve_processor.get_patch_content(patch['owner'], patch['project'], patch['hash'])
                                }
                                for patch in _cve.get('patch_urls')
                            ],
                            "sw_version": f"{tag}",
                            "sw_version_wget": f"{patch_urls[0]['repo_url']}/archive/refs/tags/{tag}.zip",
                            "description": _cve.get('description')
                        }
                    else:
                        raise ValueError(f"❌ We were not able to find the affected version tag in the repo. Please provide the code_url argument")

            else:
                if code_url:
                    cve = {
                        "published_date": cve_processor.get_published_date(_cve['id']),
                        "patch_commits": [],
                        "sw_version": "n/a",
                        "sw_version_wget": code_url,
                        "description": _cve.get('description')
                    }
                else:
                    raise ValueError(f"❌ We were not able to find patch URLs, so please provide the code_url argument")
                
            potential_advisories = _cve.get("other_urls")
            sec_advs = []
            if potential_advisories:
                keywords = ['security', 'advisory', 'advisories', 'bounties', 'bounty']
                for url in potential_advisories:
                    url_words = url.split('/')
                    if any(keyword in url_words for keyword in keywords):
                        sec_adv_content = scraper_utils.scrape(url)
                        sec_advs.append({
                                            "url": url,
                                            "content": sec_adv_content
                                        })
            cve['sec_advs'] = sec_advs

            cwe = _cve.get("cwe")
            if cwe:
                cve["cwe"] = [{"id": c['id'], "value": c['value']} for c in cwe]

        # 3) download the vulnerable tag version of the repo
        subprocess.run("rm -rf simulation_environments/*", shell=True)
        os.chdir("simulation_environments/")
        subprocess.run(f"wget {cve['sw_version_wget']}", shell=True)

        zip_name = [file for file in os.listdir(".") if file.endswith(".zip")][0]
        subprocess.run(f"unzip {zip_name}", shell=True)

        dir_name = [file for file in os.listdir(".") if os.path.isdir(file)][0]
        os.chdir(dir_name)
        os.environ['REPO_PATH'] = f"{dir_name}/"

        # 4) get the directory tree of the repo
        cve['dir_tree'] = subprocess.run("tree -d", shell=True, capture_output=True).stdout.decode("utf-8")
        cve['repo_path'] = f"{dir_name}/"
        os.chdir(cur_dir)

        return cve
