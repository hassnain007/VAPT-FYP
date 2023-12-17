
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
from modules.network import service_detections

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

    def common_scan(self,stealth=None,sv=None):
        # print_figlet()

        if not self.protocol:
            protocol = "TCP"
        else:
            protocol = self.protocol

        ports = [21,22,80,443,3306,14147,2121,8080,8000]
        open_ports = []
        filtered_ports = []
        open_or_filtered = []

        if stealth:
            logging.info("Starting - Stealth TCP Port Scan\n")
            for port in ports:
            
                scan = self.syn_scan(port=port,stealth=stealth)
        
                if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }

                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)
        else:
            if protocol == "TCP":
                logging.info("Starting - TCP Connect Port Scan\n")
            elif protocol == "UDP":
                logging.info("Starting - UDP Port Scan\n")
            else:
                pass

        for port in ports:
            
            scan = self.port_Scan_Tcp_Udp(port=port)
        
            if scan:
                ports_saved = {
                    "open": open_ports,
                    "filtered": filtered_ports,
                    "open/filtered": open_or_filtered
                }

                open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)

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


    def scan_range_of_ports(self,start,end=None,stealth=None,sv=None):
        open_ports = []
        filtered_ports = []
        open_or_filtered = []
        protocol = self.protocol

        if not protocol:
            protocol = "TCP"

        
        if protocol == "TCP" and stealth:
            logging.info("Starting - TCP Stealth Port Scan\n")
        elif protocol == "TCP" and not stealth:
            logging.info("Starting - TCP Connect Port Scan\n")
        elif protocol == "UDP":
            logging.info("Starting - UDP Port Scan\n")
        else:
            pass

        if end:
            for port in range(start,end):
                scan = self.port_Scan_Tcp_Udp(stealth,port=port)

                if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }

                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=port)

            if open_ports or filtered_ports or open_or_filtered:
                total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

                # print_figlet()
                logging.info(f"Founded {total} ports!")

                for port in open_ports:
                    logging.info(f"Port: {port} - Open")
                for port in filtered_ports:
                    logging.warning(f"Port: {port} - Filtered")
                for port in open_or_filtered:
                    logging.info(f"Port: {port} - Open/Filtered")
        else:
            scan = self.syn_scan(stealth)

            if scan:
                    ports_saved = {
                        "open": open_ports,
                        "filtered": filtered_ports,
                        "open/filtered": open_or_filtered
                    }

                    open_ports, filtered_ports, open_or_filtered = self.handle_port_response(ports_saved=ports_saved,response=scan,port=start)

            if open_ports or filtered_ports or open_or_filtered:
                total = len(open_ports) + len(filtered_ports) + len(open_or_filtered)

                # print_figlet()
                logging.info(f"Founded {total} ports!")

                for port in open_ports:
                    logging.info(f"Port: {port} - Open")
                for port in filtered_ports:
                    logging.debug(f"Port: {port} - Filtered")
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

    def host_discovery_using_arp_requests(ip_range, cidr=24, timeout=5):
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

