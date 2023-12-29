
import bruteforcing_ssh_ftp
import network_module
import service_detections 
import sys
sys.path.insert(0, 'D:/final_clonning  --repository--fyp')
from core.colors import *

def network_menu():
    print(f"\t\t{green}===== Network Scan Menu =====")
    print(f"\t\t{green}[1]. syn scan (tcp/udp)")
    print(f"\t\t{green}[2]. tcp connect scan(tcp/udp)")
    print(f"\t\t{green}[3]. Service detection")
    print(f"\t\t{green}[4]. Scan range of ports")
    print(f"\t\t{green}[5]. Bruteforcing SSH and FTP")
    print(f"\t\t{green}[6]. Operating system detection")
    print(f"\t\t{green}[7]. Host discovery (icmp)")
    print(f"\t\t{green}[8]. Host discovery (arp)")
    print(f"\t\t{green}[9]. exit")
    choice = input("Enter your choice: ")
    return choice

def runNet(choice):
    
    if choice == "1":
        #syn scan
        scanner = network_module.Complete_Network_Scanner()
        target = input("Enter target IP: ")
        protocol = input("Enter protocol to use (ICMP/UDP/TCP): ")
        start_port = int(input("Enter  port to scan:    /t e.g:80"))
              
        scanner.set_protocol(protocol)
        scanner.set_target(target)
        scanner.scan_range_of_ports(start=start_port,  stealth=True, sv=False)
    elif choice == "2":
        #tcp connect scan
         # ****  syn scan  ****
        scanner = network_module.Complete_Network_Scanner()
        target = input("Enter target IP: ")
        protocol = input("Enter protocol to use (UDP/TCP): ")
        start_port = int(input("Enter  port to scan:    /t e.g:80"))
              
        scanner.set_protocol(protocol)
        scanner.set_target(target)
        scanner.scan_range_of_ports(start=start_port,  stealth=False, sv=False)
        
    elif choice == "3":
        # ****  Service Detection ******    
        # Get user input for IP address and ports
        scanner = network_module.Complete_Network_Scanner()
        ip_address = input("Enter the target IP address: ")
        ports_input = input("Enter the target port(s), separated by commas: ")

        # Convert the ports input to a list of integers
        ports = [int(port.strip()) for port in ports_input.split(',')]

        # Call the scan_for_services function
        service_detections.scan_for_services(ip_address, ports)

    elif choice == "4":
        #  **** scan range of ports ****
        scanner = network_module.Complete_Network_Scanner()
        target = input("Enter target IP: ")
        protocol = input("Enter protocol to use (ICMP/UDP/TCP): ")
        start_port = int(input("Enter start port: "))
        end_port = int(input("Enter end port (press Enter for single port): ") or start_port)
        stealth = input("Enable stealth mode? (y/n): ").lower() == 'y'

        scanner.set_protocol(protocol)
        scanner.set_target(target)
        scanner.scan_range_of_ports(start=start_port, end=end_port, stealth=stealth, sv=False)
    
    elif choice == "5":
        # Bruteforcing SSH and FTP
        
        host_input = input('[+] Target Address: ')
        protocol_input = input('[+] Protocol (ssh/ftp): ')
        credentials_file_input = input('[+] Username:Password File: ')
        print('\n')
        bruteforcing_ssh_ftp.bruteforce_ssh_and_ftp(host_input, protocol_input, credentials_file_input)
    
        
    elif choice == "6":
        #  **** Host Discovery using icmp or ping ****
        scanner = network_module.Complete_Network_Scanner()
        ip_range = input("Enter IP range for host discovery: ")
        cidr = int(input("Enter CIDR (default is 24): ") or 24)
        scanner.set_my_ip(ip_range)
        scanner.discover_net(cidr=cidr)
    
    elif choice == "7":
        scanner = network_module.Complete_Network_Scanner()
        ip_range = input("Enter IP range for host discovery: ")
        cidr = int(input("Enter CIDR (default is 24): ") or 24)
        scanner.host_discovery_using_arp_requests(ip_range ,cidr=cidr)

    elif choice == "9":
        print("Exiting...")
        sys.exit()
        
    else:
        print("Invalid choice. Please enter a valid option.")



if __name__ == "__main__":
    while True:
        choice = network_menu()
        runNet(choice)