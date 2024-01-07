import argparse
import os

from core.colors import *
from core.config import api_key
from modules.web.tech_detect import scan_domain, scan_file
from modules.web.wFuzzer import Fuzzer
from modules.web.CMSDetect.scanner import *
from modules.web.CMSExploit import exploiter
from modules.web.form_bruter import crack
vapt_path = os.environ['PYTHONPATH'].split(os.pathsep)
project_root = os.path.abspath(vapt_path[0])

def web_menu():
    print(f"\t\t{green}===== Web Scan Menu =====")
    print(f"\t\t{green}[1]. Tech Detection")
    print(f"\t\t{green}[2]. Directory Fuzzer")
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
        url = input(f"{green}Enter Target url: ")
        word_list = os.path.join(project_root, "db", "directory-list-2.3-small.txt")
        Fuzz = Fuzzer(
        wordlist=word_list,
        url=url,
        threads=3,
        output=None,
        extended=False,
        quite=False,
        status_codes=None,
        extensions=None,
        auto=False,
        force=True 
        )
        Fuzz.run()
        
    elif choice == "3":
        if api_key != None:
            choice = input(f"{que}{green}Enter 'F' to scan file and 'D' to scan domain: ")
            if choice == 'F':
                filename = input(f"{que}{green}Enter the name of file :")
                filename = os.path.join(filename)
                full_scan(url,urlfile=filename,outfile=None,api_key=api_key)
            elif choice == 'D':
                url = input(f"{que}{green}Enter the name of url:")
                full_scan(url,urlfile=None,outfile=None,api_key=api_key)
        else:
            print(f"{bad}{red} Api key not set")
    elif choice == "4":
        print("CMS Exploit")    
    elif choice == "5":
        url = input("Enter Url: ")
        uname = input("Enter Username to Scan: ")
        user_sel = input("Enter User Selector: ")
        pass_sel = input("Enter Password Selector: ")
        pass_list = os.path.join(project_root, "db", "10k-most-common.txt")
        if (url and user_sel and pass_sel and uname) != "":
            crack(url,uname,user_sel,pass_sel,pass_list)
        else:
            print("\nPlease enter all fields.\n")
    else:
        print("Invalid choice. Please enter a valid option.")
    pass
    
