from cgitb import grey
import os
import socket
from threading import Thread
from scapy.all import ARP, Ether, srp, IP, TCP, sr1,sr,ICMP,send,UDP
import concurrent.futures
from termcolor import colored
from colorama import Fore, Style , init
init()
from cgitb import grey

def tcp_connect_scan(ip_address, port, verbose=True, F_range=False):
    if  F_range:
        print(colored("Running Scan on ", 'white') + colored(ip_address, 'green'))
    """

    Scans a port for an open connection using TCP.

    

    Args:

        ip_address (str): The IP address to scan.

        port (int): The port number to scan.

        verbose (bool): Whether to print the status of the port. Default is True.

        range (bool): Whether to scan a range of ports. Default is False.

    

    Returns:

        str: The status of the port ("Open", "Closed or Filtered").

    """

    try:

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

            s.settimeout(1)

            s.connect((ip_address, port))

            status = "Open"


    except Exception:

        status = "Closed"


    

    print(colored(f"Port {port}: ", "grey") + colored(status, "green" if status == "Open" else "red"))


    return status


def scan_range(target, start_port, end_port,F_range=True):
    print(colored("Running Scan on ", 'light_yellow') + colored(target, 'green'))
    open_ports = []


    for port in range(start_port, end_port+1):

        open_ports.extend(tcp_connect_scan(target, port))




def scan_multiple_ports(ip_address, port_list):

    for port in port_list:

        tcp_connect_scan(ip_address, port)
        


