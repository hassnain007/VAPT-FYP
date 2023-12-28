from core.colors import *
from modules.network.bruteforcing_ssh_ftp import bruteforce_ssh_and_ftp
from modules.network.network_module import Complete_Network_Scanner

def network_menu():
    print(f"\t\t{green}===== Network Scan Menu =====")
    print(f"\t\t{green}[1]. syn scan (tcp/udp)")
    print(f"\t\t{green}[2]. tcp connect scan(tcp/udp)")
    print(f"\t\t{green}[3]. Service detection")
    print(f"\t\t{green}[4]. Scan range of ports")
    print(f"\t\t{green}[5]. Bruteforcing SSH and FTP")
    print(f"\t\t{green}[5]. Operating system detection")
    choice = input("Enter your choice: ")
    return choice

def runNet(choice):
    if choice == "1":
        target = input("Enter target ip")
    elif choice == "2":
        pass
    elif choice == "3":
        pass
    elif choice == "4":
        pass
    elif choice == "5":
        host_input = input('[+] Target Address: ')
        protocol_input = input('[+] Protocol (ssh/ftp): ')
        credentials_file_input = input('[+] Username:Password File: ')
        print('\n')

        bruteforce_ssh_and_ftp(host_input, protocol_input, credentials_file_input)
    else:
        print("Invalid choice. Please enter a valid option.")


