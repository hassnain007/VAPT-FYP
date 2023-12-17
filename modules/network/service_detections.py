from importlib.resources import Package



import nmap
from tabulate import tabulate

def detect_services(ip_address, ports):
    print(f"Scanning target host {ip_address}")
    if not isinstance(ports, list):
        ports = [ports]
    nm = nmap.PortScanner()
    nm.scan(ip_address, arguments=f'-p {",".join(str(p) for p in ports)}')
    services = nm[ip_address]['tcp']
    open_ports = []
    for port, service in services.items():
        if service['state'] == 'open':
            open_ports.append([port, service['name']])
    print(tabulate(open_ports, headers=['Port', 'Service'], tablefmt='pretty'))

# Usage example
try:
    detect_services('192.168.100.89', 139)
except nmap.nmap.PortScannerError as e:
    print(f"An error occurred: {e}")
