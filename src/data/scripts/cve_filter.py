import os, re, json
from typing import Generator
import pprint
import csv
from urllib.parse import urlparse

CVE_DIR = os.path.join(os.path.dirname(__file__), '../data', 'cvelistV5/cves')

def cves_data(year: int = None) -> Generator[dict, None, None]:
    """
    Returns a generator of CVE data.
    """
    if year:
        cve_dir = os.path.join(CVE_DIR, str(year))
    else:
        cve_dir = CVE_DIR
    
    for subdir, _, files in os.walk(cve_dir):
        for file in files:
            if file.endswith('.json'):
                with open(os.path.join(subdir, file), 'r') as f:
                    cves_data = json.load(f)
                yield cves_data

def get_cve_by_id(cve_id: str) -> dict | None:
    """
    Returns the CVE data for the given CVE ID.
    """
    if not cve_id.startswith("CVE-") or len(cve_id.split('-')) != 3:
        raise ValueError("Invalid CVE ID format. Expected format: CVE-YYYY-NNNNNNN")
    
    # Extract year and numeric portion from the CVE ID
    _, year, number = cve_id.split('-')
    year = int(year)
    number = int(number)
    
    # Calculate the subdirectory
    sub_dir = f"{year}/{number // 1000}xxx"
    
    # Construct the full file path
    file_path = os.path.join(CVE_DIR, sub_dir, f"{cve_id}.json")

    # Check if the file exists
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='ISO-8859-1') as f:
            cve_data = json.load(f)
        print(cve_data)
        return cve_data
    else:
        print(f"{file_path} does not exist")
        return None
    
def dump_dict_to_csv(data_dict, filename):
    """Dump a dictionary to a CSV file."""
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        for key, value in data_dict.items():
            writer.writerow([key, value[0], value[1]])

def read_csv_to_dict(filename):
    """Read a CSV file and convert it to a dictionary."""
    dic={}
    with open(filename, mode='r', encoding='utf-8') as file:
        reader = csv.reader(file)        
        for row in reader:
            key = row[0]
            adv = row[1]
            com = row[2]
            dic[key]=[adv,row]
    return dic

def make_big_json(year):
    big_json=[]
    gen=cves_data(year)
    for cve in gen:
        big_json.append(cve)
    with open('./cve_'+str(year)+'_big.json', 'w') as f:
        json.dump(big_json, f)

def load_big_json(year):
    with open('./cve_'+str(year)+'_big.json', 'r') as f:
        return json.load(f)
    
def advisory(year):
    try:
        cves=load_big_json(year)
    except:
        make_big_json(year)
        cves=load_big_json(year)
    adv_list=['huntr','hackerone','exploit','securitylab','cvedetails','advisories', 'advisory']
    # adv_list=['huntr']
    count=0
    total=0
    site_frequency={}
    repo_frequency={}
    d={}
    for cve in cves:
        total+=1
        exp=''
        com=''
        ver=''
        for container in cve['containers']:
            if 'affected' in cve['containers'][container]:
                if 'versions' in cve['containers'][container]['affected'][0]:
                    if cve['containers'][container]['affected'][0]['versions'][0]:
                        if cve['containers'][container]['affected'][0]['versions'][0]['version']!='n/a':
                            ver=cve['containers'][container]['affected'][0]['versions'][0]
            if 'references' in cve['containers'][container]:
                for reference in cve['containers'][container]['references']:
                    if 'tags' in reference:
                        if 'exploit' in reference['tags']:
                            exp=reference['url']
                    if 'url' in reference:
                        parsed_url = urlparse(reference['url'])
                        domain = parsed_url.netloc
                        if domain.startswith('www.'):
                            domain = domain[4:]
                        if domain not in site_frequency:
                            site_frequency[domain]=0
                        site_frequency[domain]+=1 

                        if 'commit/' in reference['url']:
                            com=reference['url']
                            try:
                                repo=reference['url'][reference['url'].index("github.com/")+11:reference['url'].index("commit/")-1]
                                if repo not in repo_frequency:
                                    repo_frequency[repo]=0
                                repo_frequency[repo]+=1
                            except:
                                pass
                        for adv in adv_list:
                            if adv in reference['url']:
                                exp=reference['url']
                                break
                        
        if ver and com and exp:
            # print(cve['cveMetadata']['cveId'], exp, com)
            # d[cve['cveMetadata']['cveId']]=[exp,com]
            count+=1
    print(count, total)
    # dump_dict_to_csv(d, f"advisory_{year}.csv")
    # pprint.pp(sorted(list(repo_frequency.items()), key= lambda x:x[1], reverse=True)[:50])

if __name__ == "__main__":
    advisory(2024)
    pass
    