from core.colors import *
from modules.network import network_module
from modules.web import wFuzzer
import argparse
import logging
import os
import socket
import sys
import textwrap
import time
from colorama import Fore

white = Fore.WHITE
black = Fore.BLACK
red = Fore.RED
reset = Fore.RESET
blue = Fore.BLUE
cyan = Fore.CYAN
yellow = Fore.YELLOW
green = Fore.GREEN
magenta = Fore.MAGENTA

clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')


def print_figlet(sleep=True):
    clear()
    print(textwrap.dedent(
        f'''
     78            79  99999999999999999999    99999999999999999999  
      78          79   66666666666666666666    66666666666666666666   
       78        79           7777                    7777 
        78      79            5645                    5645   
         78    79             3214                    3214    
          78  79    [ + ]     6542         [ + ]      6542    
            78      [ + ]     6587         [ + ]      6587              fyp project Group:13

    
        [[cyan]*[/cyan]]Starting...
    '''
    ))

    if sleep:
        try:
            time.sleep(4.5)
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Network & web testing Tool",
                                     usage="\n for network: controller.py -sC 192.168.0.106\n\tcontroller.py -sA 192.168.0.106")

    parser.add_argument('-scP', "--scan-common", help="Scan common ports", action="count")
    parser.add_argument('-saP', "--scan-all", help="Scan all ports", action="count")
    parser.add_argument('-sOS', "--scan-os", help="Scan OS", action="count")
    parser.add_argument('-sPorts', "--scan-port", help="Scan defined port")
    parser.add_argument('-sServices', "--scan-service", help="Try to detect service running")
    parser.add_argument('-hd', "--discover", help="Discover hosts in the network", action="count")
    parser.add_argument('-p', "--protocol", help="Protocol to use in the scans. ICMP,UDP,TCP.",
                        type=str, choices=['ICMP', 'UDP', 'TCP'], default=None)
    parser.add_argument('-i', "--interface", help="Interface to use", default=None)
    parser.add_argument('-t', "--timeout", help="Timeout to each request", default=5, type=int)
    parser.add_argument('-st', "--stealth", help="Use Stealth scan method (TCP)", action="count")
    parser.add_argument('-v', "--verbose", action="count")
    parser.add_argument('Target', nargs='?', default=None)
    # arguments for fuzzer
    parser.add_argument("-w", "--wordlist", help="path to wordlist")
    parser.add_argument("-u", "--url", help="address of remote site")
    parser.add_argument("-t", "--threads", help="number of threads to use", default=20)
    parser.add_argument("--auto", action="store_true", help="shows response on the basis of the number of words")
    parser.add_argument("-f", "--force", action="store_true", help="use to force status check")
    parser.add_argument("-a", "--user-agent", help="add custom user agent")
    parser.add_argument("-c", "--cookies", help="pass cookies as a string")
    parser.add_argument("-fs", "--forward-slash", help="append a forward slash to all requests", action="store_true")
    parser.add_argument("-e", "--extended", help="show extended urls", action="store_true")
    parser.add_argument("-p", "--proxy", help="Proxy to use for requests [http(s)://host:port]")
    parser.add_argument("-q", "--quite", action="store_true", help="does not print banner and other stuff")
    parser.add_argument("-o", "--output", help="output to a file")
    parser.add_argument('-s', '--status-codes',
                        help='manually pass the positive status codes (default "200,204,301,302,307,403")')
    parser.add_argument("-U", "--username", help="username for basic http auth")
    parser.add_argument("-P", "--password", help="password for basic http auth")
    parser.add_argument("-x", "--extensions", help="file extension(s) to search for")

    args = parser.parse_args()

    if args.wordlist or args.url or args.threads or args.auto or args.force or args.user_agent or args.cookies \
            or args.forward_slash or args.extended or args.proxy or args.quite or args.output or args.status_codes \
            or args.username or args.password or args.extensions:
        # Initialize Fuzzer object
        Fuzzer = wFuzzer.Fuzzer(
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
       

        # Run the Fuzzer
        Fuzzer.run()
    else:
        # Initialize Network Scanner object
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()

        scanner = network_module.Complete_Network_Scanner(target=args.Target, my_ip=ip, protocol=args.protocol,
                                                          timeout=args.timeout, interface=args.interface)

        if args.scan_common:
            scanner.common_scan(stealth=args.stealth, sv=args.scan_service)
        elif args.scan_all:
            scanner.scan_range_of_ports(start=0, end=65535, stealth=args.stealth, sv=args.scan_service)
        elif args.scan_port:
            try:
                scanner.scan_range_of_ports(start=int(args.scan_port.split(',')[0]),
                                            end=int(args.scan_port.split(',')[1]), stealth=args.stealth,
                                            sv=args.scan_service)
            except:
                scanner.scan_range_of_ports(start=args.scan_port, stealth=args.stealth, sv=args.scan_service)
        elif args.discover:
            scanner.discover_net()
        else:
            parser.print_help()

        if args.scan_os:
            scanner.os_scan()