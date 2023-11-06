#!/usr/bin/python3

import os
import socket
from threading import Thread
from scapy.all import ARP, Ether, srp, IP, TCP, sr1
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
        
def syn_scan(target_ip, port):
    response = sr1(IP(dst=target_ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x12:  # SYN-ACK flag
            return f"Port {port} is open on {target_ip}"
    return f"Port {port} is closed on {target_ip}"

def perform_syn_scan(ip_addresses, port):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_ip = {executor.submit(syn_scan, ip, port): ip for ip in ip_addresses}
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            result = future.result()
            open_ports.append(result)
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
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: vanilla_scan_single_host(ip_address, port), ports))
        open_ports.extend([port for port in results if port is not None])
    return open_ports

def xmas_scan_single_host(ip_address, port):
    response = sr1(IP(dst=ip_address) / TCP(dport=port, flags="FPU"), timeout=1, verbose=False)
    if response and response.haslayer(TCP):
        if response[TCP].flags == 0x14:  # RST packet (port closed)
            return None
    return port

def xmas_scan(ip_address, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: xmas_scan_single_host(ip_address, port), ports))
        open_ports.extend([port for port in results if port is not None])
    return open_ports

if __name__ == "__main__":
    # ... (your existing code for the main function)
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3389]
    network_prefix = input("Enter the network prefix (e.g., 192.168.1.0): ")
    subnet_mask = input("Enter the subnet mask (e.g., 24): ")

    hosts, active_hosts = discover_hosts(network_prefix, subnet_mask)
    if isinstance(hosts, list):
         print("Discovered host ip addresses:")
    for host in hosts:
        print(f"IP: {host['ip']}, MAC: {host['mac']}")
        
        
    else:
            print(hosts)    

    
    syn_open_ports = perform_syn_scan(active_hosts, COMMON_PORTS)
    vanilla_open_ports = [vanilla_scan(ip, COMMON_PORTS) for ip in active_hosts]
    xmas_open_ports = [xmas_scan(ip, COMMON_PORTS) for ip in active_hosts]

    print("\nOpen ports found by SYN scan:")
    for ip, ports in zip(active_hosts, syn_open_ports):
        print(f"Host: {ip}, Open Ports: {ports}")

    print("\nOpen ports found by Vanilla scan:")
    for ip, ports in zip(active_hosts, vanilla_open_ports):
        print(f"Host: {ip}, Open Ports: {ports}")

    print("\nOpen ports found by XMAS scan:")
    for ip, ports in zip(active_hosts, xmas_open_ports):
        print(f"Host: {ip}, Open Ports: {ports}")
