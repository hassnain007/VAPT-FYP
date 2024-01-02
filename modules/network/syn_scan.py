from scapy.all import IP, TCP, UDP, sr1

from termcolor import colored

from colorama import init

init()

def syn_scan(target, port, protocol="tcp"):
    
    open_ports = []


    if not isinstance(target, str) or not isinstance(port, int):

        print(colored("Invalid target or port. Target must be a string and port must be an integer.", "red"))

        return


    try:

        if protocol == "tcp":

            pkt = IP(dst=target) / TCP(dport=port, flags="S")

            scan = sr1(pkt, timeout=5, verbose=0)


            if scan is None:

                print(colored(f"Port {port}: Filtered", "yellow"))

            elif scan.haslayer(TCP):

                if scan.getlayer(TCP).flags == 0x12: # 0x12 SYN+ACk

                    IP(dst=target) / TCP(dport=port, flags="R") # Send a RST packet

                    print(colored(f"Port {port}: Open", "green"))

                    open_ports.append(port)

                elif scan.getlayer(TCP).flags == 0x14:

                    print(colored(f"Port {port}: Closed", "white"))

        elif protocol == "udp":

            pkt = IP(dst=target) / UDP(dport=port)

            scan = sr1(pkt, timeout=5, verbose=0)


            if scan is None:

                print(colored(f"Port {port}: Open|Filtered", "yellow"))

            elif scan.haslayer(UDP):

                print(colored(f"Port {port}: Open", "green"))

                open_ports.append(port)

    except Exception as e:

        print(colored(f"Error creating or sending packet: {e}", "red"))

        return


    return open_ports


def perform_syn_scan(target, ports,protocol ):
    print(colored("Running Scan on ", 'blue') + colored(target, 'red'))
    open_ports = []

    for port in ports:
        result = syn_scan(target, port,protocol)
        open_ports.append({port: result})

    return open_ports

def scan_range(target, start_port, end_port, protocol="tcp"):
    print(colored("Running Scan on ", 'light_yellow') + colored(target, 'green'))
    open_ports = []


    for port in range(start_port, end_port+1):

        open_ports.extend(syn_scan(target, port, protocol))


    return open_ports




def scan_multiple_ports(ip_address, port_list):

    for port in port_list:

        syn_scan(ip_address, port)

syn_scan("192.168.100.1",23)
syn_scan("192.168.100.1",50)