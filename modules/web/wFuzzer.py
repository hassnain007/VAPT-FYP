from datetime import datetime
from random import choice
from string import ascii_lowercase, ascii_uppercase
from requests import get, head
import threading
from core.colors import *
import argparse
from os import path
import os
from concurrent.futures import ThreadPoolExecutor

vapt_path = os.environ['PYTHONPATH'].split(os.pathsep)
project_root = os.path.abspath(vapt_path[0])

class Fuzzer:
    def __init__(self, wordlist, url, threads, output, extended,extensions, status_codes, auto, force, quite):
        self.wordlist = wordlist
        self.url = url
        self.threads = threads
        self.output = output
        self.extended = extended
        self.extensions = extensions
        self.status_codes = status_codes
        self.auto = auto
        self.force = force
        self.quite = quite

        self.base_url = self.setup_base_url()
        self.valid = self.setup_valid_status_codes()

        if self.output is not None:
            self.f = open(self.output, "w+")

    def setup_base_url(self):
        if self.url is not None:
            base_url = self.url
            if not base_url.startswith('http://') and not base_url.startswith('https://'):
                base_url = 'http://' + base_url
            if not base_url.endswith('/'):
                base_url += '/'
            return base_url
        return None

    def setup_valid_status_codes(self):
        valid = [200, 204, 301, 302, 403]
        if self.status_codes is not None:
            status_codes = self.status_codes.replace(' ', '').split(",")
            valid = [int(i) for i in status_codes]
        return valid


    def find_s(self, wordlist):
        words = wordlist.split()
        for i in words:
            try:
                r = head(self.base_url + i,)
                if r.status_code in self.valid:
                    if r.status_code in [200,204]:
                        color = green
                    elif r.status_code in [401,403]:
                        color = red
                    elif r.status_code in [301,302]:
                        color = blue
                    if not self.extended:
                        print(f"{blue}/{i} {color}{r.status_code}{end}")
                    else:
                        print(self.base_url + i + " (Status: %s)" % (r.status_code))
                    if self.output is not None:
                        with open(self.output, "a") as f:
                            f.write(self.base_url + i + " (Status: %s)" % (r.status_code) + "\n")
            except KeyboardInterrupt:
                print(f"{bad}Interrupted")
            except:
                pass
            
    def find_w(self, wordlist):
        path = self.random_path()
        r = get(self.base_url + path).content
        nw = len(r.split(b' '))
        for i in wordlist:
            r = get(self.base_url + i).content
            r = len(r.split(b' '))
            r -= len(i.split(' ')) - 1
            if r != nw:
                if not self.extended:
                    print("/" + i + " (Words: %s)" % (r))
                else:
                    print(self.base_url + i + " (Words: %s)" % (r))
                if self.output is not None:
                    with open(self.output, "a") as f:
                        f.write(self.base_url + i + " (Words: %s)" % (r) + "\n")


    def check(self):
        if self.auto:
            return False
        if self.force:
            return True
        path = open(self.wordlist).read()
        r = get(self.base_url + path)
        if r.status_code in self.valid:
            if not self.auto:
                print("[+] Wildcard response found /" + path + " (" + str(r.status_code) + ")")
                print("[+] Use --auto for automatically showing available pages")
                print("[+] Use -f to force status code check")
            return False
        else:
            return True

    def run(self):
        ex = self.extensions
        if self.extensions is not None:
            if len(self.extensions) > 1:
                ex = ', '.join(self.extensions)
            else:
                ex = ''.join(self.extensions)

        banner = """
        =====================================================
        Fuzzer v1.0                                 
        =====================================================
        [+] Mode         : dir
        [+] Url/Domain   : %s
        [+] Threads      : %s
        [+] Wordlist     : %s
        [+] Status codes : %s
        [+] Extensions   : %s
        =====================================================
        %s Starting Fuzzer
        ======================================================""" % (
            self.base_url, self.threads, self.wordlist, self.valid, ex, datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

        if not self.quite:
            print(banner)
            
        w = open(self.wordlist).read().splitlines()
        threads = []

        if self.check():
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                executor.map(self.find_s,w)
                
        #     for i in w:
        #         x = threading.Thread(target=self.find_s, args=(i,))
        #         x.daemon = True
        #         threads.append(x)
        #         x.start()
        elif self.auto:
            for i in w:
                x = threading.Thread(target=self.find_w, args=(i,))
                x.daemon = True
                threads.append(x)
                x.start()

        for a, b in enumerate(threads):
            b.join()

        fin = """=====================================================
        %s Finished
        =====================================================""" % (datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

        if not self.quite:
            print(fin)

        if self.output is not None:
            self.f.close()


if __name__ == "__main__":
    word_list = os.path.join(project_root, "db", "directory-list-2.3-small.txt")
    
    Fuzzer = Fuzzer(
        wordlist=word_list,
        url="https://iulms.edu.pk/",
        threads=10,
        output=None,
        extended=False,
        quite=False,
        status_codes=None,
        extensions=None,
        auto=False,
        force=True 
    )

    Fuzzer.run()
    pass