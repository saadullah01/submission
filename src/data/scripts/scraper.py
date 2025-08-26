import cve_filter
import cve_processor
import data_processor
import json
from scraper_utils import scrape
import tqdm

def scrape_huntr():
    dic = cve_filter.read_csv_to_dict('./huntr_2024.csv')
    for cve in dic:
        info = cve_processor.get_cve_by_id(cve)
        scrape_text = scrape(dic[cve][0])
        data={}
        data['id']=cve
        data['description']=info['description']+' '+scrape_text
        data['project']=info['patch_urls'][0]['project']
        data['git_url']=info['patch_urls'][0]['repo_url']
        data['hash']=info['patch_urls'][0]['hash']
        with open('./huntr_2024/'+cve+'.json', 'w') as fp:
            json.dump(data, fp)

def scrape_advisory(year):
    dic = cve_filter.read_csv_to_dict(f'./advisory_{year}.csv')
    for cve in tqdm.tqdm(list(dic.keys())[45:]):
        info = cve_processor.get_cve_by_id(cve)

        # Focus only on cves with single patch commit
        if(len(info['patch_urls'])>1):
            continue

        try:
            data={}
            data['id']=cve
            data['description']=info['description']
            data['project']=info['patch_urls'][0]['project']
            data['git_url']=info['patch_urls'][0]['repo_url']
            data['hash']=info['patch_urls'][0]['hash']
            data['cwe']=' '.join(info['cwe'])
            data['version_data']=info['version_data']

            # # Get git diff in text format
            patch = data_processor.get_commit_data(info['patch_urls'][0]['owner'], data['project'], data['hash'])
            data['patch']=patch['msg']+'\n'+'\n'.join(['Filename: '+file['file_name']+':\n'+'\n'.join([hunk['header']+'\n'+hunk['patch'] for hunk in file['hunks']]) for file in patch['file_patch']])
            
            # # Scrape the advisory
            scrape_text = scrape(dic[cve][0])
            data['security_advisory']=scrape_text

            # # Write the json
            with open(f'./advisory_{year}/'+cve+'.json', 'w') as fp:
                json.dump(data, fp)
        except:
            pass

if __name__ == '__main__':
    # print(scrape("https://github.com/sigstore/sigstore-go/security/advisories/GHSA-cq38-jh5f-37mq"))
    scrape_advisory(2024)
    pass