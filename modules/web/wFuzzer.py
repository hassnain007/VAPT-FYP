from datetime import datetime
from random import choice
from string import ascii_lowercase, ascii_uppercase
from requests import get, head
import threading
import argparse
from os import path

class Fuzzer:
    def __init__(self, wordlist, url, threads, cookies, useragent, output, username, password, extended, proxy, extensions, forward_slash, status_codes, auto, force, quite):
        self.wordlist = wordlist
        self.url = url
        self.threads = threads
        self.cookies = cookies
        self.useragent = useragent
        self.output = output
        self.username = username
        self.password = password
        self.extended = extended
        self.proxy = proxy
        self.extensions = extensions
        self.forward_slash = forward_slash
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
        valid = [200, 204, 301, 302, 307, 403]
        if self.status_codes is not None:
            status_codes = self.status_codes.replace(' ', '').split(",")
            valid = [int(i) for i in status_codes]
        return valid

    def random_path(self):
        chars = ascii_lowercase + ascii_uppercase
        newstr = 'totallynotavalidpage'
        for i in range(15):
            newstr += choice(chars)
        return newstr

    def find_s(self, wordlist):
        for i in wordlist:
            r = head(self.base_url + i, headers=self.headers, proxies=self.proxy, auth=self.auth)
            if r.status_code in self.valid:
                if not self.extended:
                    print("/" + i + " (Status: %s)" % (r.status_code))
                else:
                    print(self.base_url + i + " (Status: %s)" % (r.status_code))
                if self.output is not None:
                    with open(self.output, "a") as f:
                        f.write(self.base_url + i + " (Status: %s)" % (r.status_code) + "\n")

    def find_w(self, wordlist):
        path = self.random_path()
        r = get(self.base_url + path).content
        nw = len(r.split(' '))
        for i in wordlist:
            r = len(get(self.base_url + i, headers=self.headers, proxies=self.proxy, auth=self.auth).content.split(' '))
            r -= len(i.split(' ')) - 1
            if r != nw:
                if not self.extended:
                    print("/" + i + " (Words: %s)" % (r))
                else:
                    print(self.base_url + i + " (Words: %s)" % (r))
                if self.output is not None:
                    with open(self.output, "a") as f:
                        f.write(self.base_url + i + " (Words: %s)" % (r) + "\n")

    def chunk(self, seq, num):
        avg = len(seq) / float(num)
        out = []
        last = 0.0
        while last < len(seq):
            out.append(seq[int(last):int(last + avg)])
            last += avg
        return out

    def check(self):
        if self.auto:
            return False
        if self.force:
            return True
        path = self.random_path()
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

        w = self.chunk(self.wordlist, self.threads)
        threads = []

        if self.check():
            for i in w:
                x = threading.Thread(target=self.find_s, args=(i,))
                x.daemon = True
                threads.append(x)
                x.start()
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
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--wordlist", help="path to wordlist")
    parser.add_argument("-u", "--url", help="address of remote site")
    parser.add_argument("-t", "--threads", help="number of threads to use", default=20)
    parser.add_argument("--auto", action="store_true", help="shows response on basis of number of words")
    parser.add_argument("-f", "--force", action="store_true", help="use to force status check")
    parser.add_argument("-a", "--user-agent", help="add custom user agent")
    parser.add_argument("-c", "--cookies", help="pass cookies as a string")
    parser.add_argument("-fs", "--forward-slash", help="append a forward slash to all requests", action="store_true")
    parser.add_argument("-e", "--extended", help="show extended urls", action="store_true")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests [http(s)://host:port]")
    parser.add_argument("-q", "--quite", action="store_true", help="doesnt print banner and other stuff")
    parser.add_argument("-o", "--output", help="output to a file")
    parser.add_argument('-s', '--status-codes', help='manually pass the positive status codes (default "200,204,301,302,307,403")')
    parser.add_argument("-U", "--username", help="username for basic http auth")
    parser.add_argument("-P", "--password", help="password for basic http auth")
    parser.add_argument("-x", "--extensions", help="file extension(s) to search for")

    args = parser.parse_args()

    Fuzzer = Fuzzer(
        wordlist=args.wordlist,
        url=args.url,
        threads=args.threads,
        cookies=args.cookies,
        useragent=args.user_agent,
        output=args.output,
        username=args.username,
        password=args.password,
        extended=args.extended,
        proxy=args.proxy,
        extensions=args.extensions,
        forward_slash=args.forward_slash,
        status_codes=args.status_codes,
        auto=args.auto,
        force=args.force,
        quite=args.quite
    )

    Fuzzer.run()
