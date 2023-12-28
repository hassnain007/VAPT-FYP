import argparse

from core.colors import *
from modules.web.tech_detect import scan_domain, scan_file
from modules.web.wFuzzer import Fuzzer
from modules.web.CMSDetect.scanner import *
from modules.web.CMSExploit import exploiter
from modules.web.form_bruter import crack


def web_menu():
    print(f"\t\t{green}===== Web Scan Menu =====")
    print(f"\t\t{green}[1]. Tech Detection")
    print(f"\t\t{green}[2]. Wordlist Fuzzer")
    print(f"\t\t{green}[3]. CMS Scanner")
    print(f"\t\t{green}[4]. CMS Exploit")
    print(f"\t\t{green}[5]. Form Bruter")
    choice = input("Enter your choice: ")
    return choice

def runWeb(choice):
    if choice == "1":
        choice = input(f"{que}{green}Enter 'F' to scan file and 'D' to scan domain ")
        if choice == 'F':
            filename = input(f"{que}{green}Enter the name of file:")
            scan_file(filename)
        elif choice == 'D':
            url = input(f"{que}{green}Enter the name of url:")
            scan_domain(url)
    elif choice == "2":
        print("Fuzzer")
    elif choice == "3":
        api_key = input("Enter Whatcms api key:")
        choice = input(f"{que}{green}Enter 'F' to scan file and 'D' to scan domain ")
        if choice == 'F':
            filename = input(f"{que}{green}Enter the name of file :")
            filename = os.path.
            full_scan(url,urlfile=filename,outfile=None,api_key=api_key)
        elif choice == 'D':
            url = input(f"{que}{green}Enter the name of url:")
            full_scan(url,urlfile=None,outfile=None,api_key=api_key)
    elif choice == "4":
        print("Exploit")    
    elif choice == "5":
        print("Form Bruteforcing")       
    else:
        print("Invalid choice. Please enter a valid option.")
    pass
    
