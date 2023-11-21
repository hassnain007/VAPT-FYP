#!/usr/bin/python3
"""
This Module detect the tech stack on the website using the wappalyzer api
"""

from concurrent.futures import ThreadPoolExecutor as Executor  
from Wappalyzer import Wappalyzer, WebPage  

wappalyzer = Wappalyzer.latest()


def check(out,url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https'+url
    try:
        webpage = WebPage.new_from_url(url)
        tech = wappalyzer.analyze(webpage)
        if out != 'None':
            with open(out,'a') as f:
                f.write(f"{url} | {' - '.join(tech)}\n")
        else:
             return tech
    except Exception as e:
        print(e)
    
def scan_domain(domain,threads=5):
    with Executor(max_workers=int(threads)) as exe:
                    print(f"[+] Domain: {domain}")
                    exe.submit(check,domain)
    

def scan_file(file, threads, out):
    domains = []
    if file != 'None':
        with open(file, 'r') as file:
             domains = [line.strip() for line in file]
             with Executor(max_workers=int(threads)) as exe:
                for domain in domains:
                    print(f"[+] Domain: {domain}")
                    exe.submit(check, out, domain)
    
    