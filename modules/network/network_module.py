
import os
import sys
import socket
import ipaddress
import argparse
import textwrap
import logging
from scapy.all import IP, TCP, sr1, sr, ICMP, UDP, srp, ARP, Ether, send
from ctypes import *
from time import sleep
from threading import Thread
from colorama import Fore
import rpycolors
from progress.bar import ChargingBar
import concurrent.futures
import service_detections

class Complete_Network_Scanner:
    def __init__(self, target=None, my_ip=None, protocol=None, timeout=5, interface=None):
        self.target = target
        self.my_ip = my_ip
        self.protocol = protocol
        self.timeout = timeout
        self.interface = interface

    def syn_scan(self, stealth=None, port=80):
        protocol = self.protocol if self.protocol else "TCP"

        pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
        scan = sr1(pkt, timeout=self.timeout, verbose=0)

        if scan is None:
            return {port: 'Filtered'}

        elif scan.haslayer(TCP):
            if scan.getlayer(TCP).flags == 0x12:  # 0x12 SYN+ACk
                pkt = IP(dst=self.target) / TCP(dport=port, flags="R")
                send_rst = sr(pkt, timeout=self.timeout, verbose=0)
                return {port: 'Open'}
            elif scan.getlayer(TCP).flags == 0x14:
                return {port: 'Closed'}
        elif scan.haslayer(ICMP):
            if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code in [1, 2, 3, 9, 10, 13]):
                return {port: 'Filtered'}

    def port_Scan_Tcp_Udp(self, stealth=None, port=80):
        protocol = self.protocol if self.protocol else "TCP"

        if protocol == "TCP":
            pkt = IP(dst=self.target) / TCP(dport=port, flags="S")
            scan = sr1(pkt, timeout=self.timeout, verbose=0)

            if scan is None:
                return {port: 'Filtered'}
            elif scan.haslayer(TCP):
                if scan.getlayer(TCP).flags == 0x12:  # 0x12 SYN+ACk
                    pkt = IP(dst=self.target) / TCP(dport=port, flags="RA")  # Change flags to "RA"
                    send(pkt, verbose=0)  # Use send() instead of sr()
                    return {port: 'Open'}
                elif scan.getlayer(TCP).flags == 0x14:
                    return {port: 'Closed'}
                else:
                    # If the flags don't match open or closed, consider it filtered
                    return {port: 'Filtered'}
        elif protocol == "UDP":
            pkt = IP(dst=self.target) / UDP(dport=port)
            scan = sr1(pkt, timeout=self.timeout, verbose=0)

            if scan is None:
                return {port: 'Filtered'}
            elif scan.haslayer(UDP):
                return {port: 'Closed'}
            elif scan.haslayer(ICMP):
                if int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code) == 3:
                    return {port: 'Closed'}
                elif int(scan.getlayer(ICMP).type) == 3 and int(scan.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    return {port: 'Closed'}
                else:
                    # If the ICMP type and code don't match closed, consider it filtered
                    return {port: 'Filtered'}

    def handle_port_response(self, ports_saved, response, port):
        open_ports = ports_saved['open']
        filtered_ports = ports_saved['filtered']
        open_or_filtered = ports_saved['open/filtered']

        if response[port] == "Closed":
            logging.warning(f"Port: {port} - Closed")
        elif response[port] == "Open":
            logging.info(f"Port: {port} - Open")
            open_ports.append(port)
        elif response[port] == "Filtered":
            logging.warning(f"Port: {port} - Filtered")
            filtered_ports.append(port)
        elif response[port] == "Open/Filtered":
            logging.info(f"Port: {port} - Open/Filtered")
            open_or_filtered.append(port)
        else:
            pass

        return open_ports, filtered_ports, open_or_filtered

    def common_scan(self, stealth=None, sv=None):
        if not self.protocol:
            protocol = "TCP"
        else:
            protocol = self.protocol

        ports = [21, 22, 80, 443, 3306, 14147, 2121, 8080, 8000]
        open_ports = []
        filtered_ports = []
        open_or_filtered = []

        def perform_scan(port, scan_function):
            scan_result = scan_function(port=port, stealth=stealth)
            if scan_result:
                ports_saved = {
                    "open": open_ports,
                    "filtered": filtered_ports,
                    "open/filtered": open_or_filtered
                }
                self.handle_port_response(
                    ports_saved=ports_saved, response=scan_result, port=port
                )

        if stealth:
            logging.info("Starting - Stealth TCP Port Scan\n")
            for port in ports:
                perform_scan(port, self.syn_scan)
        else:
            scan_function = self.port_Scan_Tcp_Udp if protocol in {"TCP", "UDP"} else None

            if scan_function:
                logging.info(f"Starting - {protocol} Connect Port Scan\n")
                for port in ports:
                    perform_scan(port, scan_function)

        if open_ports or filtered_ports or open_or_filtered:
            total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

            print("")
            logging.info(f"Founded {total} ports!")

            for port in open_ports:
                logging.info(f"Port: {port} - Open")
            for port in filtered_ports:
                logging.warning(f"Port: {port} - Filtered")
            for port in open_or_filtered:
                logging.info(f"Port: {port} - Open/Filtered")

    

    def multi_host_syn_scan(self,targets=None, ports=None):
        open_ports_dict = {}
    
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Use list comprehension to submit tasks to the thread pool
            futures = [executor.submit(self.syn_scan, target, port) for target in targets for port in ports]

            # Iterate through the completed futures to get results
            for future in concurrent.futures.as_completed(futures):
                target, port, open_ports = future.result()
                if open_ports:
                    if target not in open_ports_dict:
                        open_ports_dict[target] = []
                    open_ports_dict[target].append(port)

    def host_discovery_using_arp_requests(ip_range, cidr=24, timeout=2):
        def is_valid_subnet(cidr):
            try:
                cidr = int(cidr)
                return 0 <= cidr <= 32
            except ValueError:
                return False

        if not is_valid_subnet(cidr):
            return "Invalid subnet mask. Please enter a number between 0 and 32.", []

        arp = ARP(pdst=ip_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_packet = ether / arp

        try:
            answered, _ = srp(arp_packet, timeout=timeout, verbose=False)
            hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
            active_ips = [host['ip'] for host in hosts]  # List of active IP addresses

            # Display formatted details
            print("Active Hosts:")
            for host in hosts:
                print(f"IP: {host['ip']}   MAC: {host['mac']}")

            return hosts, active_ips

        except Exception as e:
            return f"An error occurred during ARP request: {e}", []
        
   
        


    def send_icmp(self, target, result, index):
        target = str(target)
        host_found = []
        pkg = IP(dst=target) / ICMP()
        try:
            answers, _ = sr(pkg, timeout=3, retry=2, verbose=0, iface=self.interface if self.interface else None)
            answers.summary(lambda r: host_found.append(target))
        except Exception as e:
            logging.error(f"An error occurred during ICMP request to {target}: {e}")

        if host_found:
            result[index] = host_found[0]
    def service_Scan(self, ports):
        target_ip = self.target
        service_detections.scan_for_services(target_ip, ports)
        

    def discover_net(self, ip_range=24):
        protocol = self.protocol
        base_ip = self.my_ip

        if not protocol or protocol != "ICMP":
            logging.warning("Warning: Protocol is not supported by discover_net function! Changed to ICMP")
            protocol = "ICMP"

        if protocol == "ICMP":
            logging.info("Starting - Discover Hosts Scan")

            base_ip = f"{base_ip.split('.')[0]}.{base_ip.split('.')[1]}.{base_ip.split('.')[2]}.0/{ip_range}"

            hosts = list(ipaddress.ip_network(base_ip))
            bar = ChargingBar("Scanning...", max=len(hosts))

            sys.stdout = None
            bar.start()

            threads = [None] * len(hosts)
            results = [None] * len(hosts)

            try:
                for i in range(len(threads)):
                    threads[i] = Thread(target=self.send_icmp, args=(hosts[i], results, i))
                    threads[i].start()

                for i in range(len(threads)):
                    threads[i].join()
                    bar.next()
            except Exception as e:
                logging.error(f"An error occurred during host discovery: {e}")

            bar.finish()
            sys.stdout = sys.__stdout__

            hosts_found = [i for i in results if i is not None]

            if not hosts_found:
                logging.warn('[[red]-[/red]]Not found any host')
            else:
                print("")
                logging.info(f'{len(hosts_found)} hosts founded')
                for host in hosts_found:
                    logging.info(f'Host found: {host}')

            return True
        else:
            logging.critical("[[red]-[/red]]Invalid protocol for this scan")
            return False

# Create an instance of the Complete_Network_Scanner
scanner = Complete_Network_Scanner(target="192.168.100.1", protocol="TCP")
scanner.service_Scan([22, 53, 80, 443])

# Test the port_Scan_Tcp_Udp function for TCP ports
ports_to_test = [21, 22, 23, 53, 80, 443]

for port in ports_to_test:
    result = scanner.port_Scan_Tcp_Udp(port=port)
    print(f"TCP Port {port}: {result}")

# Test the port_Scan_Tcp_Udp function for UDP ports
scanner.protocol = "UDP"  # Switch to UDP protocol

for port in ports_to_test:
    result = scanner.port_Scan_Tcp_Udp(port=port)
    print(f"UDP Port {port}: {result}")

