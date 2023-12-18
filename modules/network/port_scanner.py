#!/usr/bin/python3

import os
import socket
from threading import Thread
from scapy.all import ARP, Ether, srp, IP, TCP, sr1,sr,ICMP,send
import concurrent.futures

# ... (your existing code for the discover_hosts function and other utility functions)

def create_arp_packet(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    return ether / arp

def send_arp_request(packet, timeout=2):
    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
        hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
        active_ips = [host['ip'] for host in hosts]  # List of active IP addresses
        return hosts, active_ips
    except Exception as e:
        return f"An error occurred: {e}", []

def is_valid_subnet(subnet_mask):
    try:
        subnet_mask = int(subnet_mask)
        return 0 <= subnet_mask <= 32
    except ValueError:
        return False

def discover_hosts(network_prefix, subnet_mask):
    if is_valid_subnet(subnet_mask):
        ip_range = f"{network_prefix}/{subnet_mask}"
        packet = create_arp_packet(ip_range)
        hosts, active_ips = send_arp_request(packet)
        return hosts, active_ips
    else:
        return "Invalid subnet mask. Please enter a number between 0 and 32.", []
        




def syn_scan(target, port):
    
    # Check if target and port are valid
    if not isinstance(target, str) or not isinstance(port, int):
        print("Invalid target or port. Target must be a string and port must be an integer.")
        return

    try:
        pkt = IP(dst=target) / TCP(dport=port, flags="S")
        scan = sr1(pkt, timeout=5, verbose=0)
    except Exception as e:
        print(f"Error creating or sending packet: {e}")
        return

    if scan is None:
        print(f"Port {port}: Filtered")
    elif scan.haslayer(TCP):
        if scan.getlayer(TCP).flags == 0x12:  # 0x12 SYN+ACk
            IP(dst=target) / TCP(dport=port, flags="R")  # Send a RST packet
            print(f"Port {port}: Open")
        elif scan.getlayer(TCP).flags == 0x14:
            print(f"Port {port}: Closed")
    elif scan.haslayer(ICMP):
        if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]):
            print(f"Port {port}: Filtered")

def perform_syn_scan(target, ports):
    print(f"[~]Scanning target :{target}")
    open_ports = []

    for port in ports:
        result = syn_scan(target, port)
        open_ports.append({port: result})

    return open_ports





def vanilla_scan_single_host(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip_address, port))
            return port
    except Exception:
        pass
    return None

def vanilla_scan(ip_address, ports):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: vanilla_scan_single_host(ip_address, port), ports))
        for port in results:
            if port is not None:
                print(f"IP: {ip_address}, Port: {port}, Status: Open")






def xmas_scan_single_host(ip_address, port):
    packet = IP(dst=ip_address) / TCP(dport=port, flags="FPU")
    response = sr1(packet, timeout=1, verbose=False)

    if response is None:
        print(f"Port {port}: Open or Filtered")
        return

    if response.haslayer(TCP):
        if response[TCP].flags == 0x14:  # RST packet
            print(f"Port {port}: Closed")
            return

    if response.haslayer(ICMP):
        if response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]:
            print(f"Port {port}: Filtered")
            return

    print(f"Port {port}: Unknown")



def xmas_scan(ip_address, ports):
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: xmas_scan_single_host(ip_address, port), ports))
        for port in results:
            if port is not None:
                print(f"IP: {ip_address}, Port: {port}, Status: Open/Filtered")

if __name__ == "__main__":
    # ... (your existing code for the main function)
 #vanilla_scan("192.168.100.1",(21,22,23,45,53,443,445,139))
    perform_syn_scan("192.168.100.89",(22,23,25,139,135,109,110,119))
 