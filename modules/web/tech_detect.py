# tech_detect.py

import threading
from Wappalyzer import Wappalyzer, WebPage
from core.colors import red, green
import warnings
warnings.filterwarnings("ignore", message="""Caught 'unbalanced parenthesis at position 119' compiling regex""", category=UserWarning )
wappalyzer = Wappalyzer.latest()

def check(out, url):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    try:
        webpage = WebPage.new_from_url(url)
        tech = wappalyzer.analyze(webpage)
        if out != 'None':
            with open(out, 'a') as f:
                f.write(f"{url} | {' - '.join(tech)}\n")
        else:
            print(green + tech)
    except Exception as e:
        print(red + str(e))

def scan_domain(domain, threads=5):
    print(f"[+] Domain: {domain}")
    thread = threading.Thread(target=check, args=('None', domain))
    thread.start()

def scan_file(file, out, threads=5):
    domains = []
    if file != 'None':
        with open(file, 'r') as file:
            domains = [line.strip() for line in file]

        for domain in domains:
            print(f"[+] Domain: {domain}")
            thread = threading.Thread(target=check, args=(out, domain))
            thread.start()

if __name__ == "__main__":
    check('None', 'https://mashriqtv.pk/')
