from scapy.all import IP, TCP, sr1, sr, ICMP, UDP, srp, ARP, Ether, send
from prettytable import PrettyTable

def host_discovery_using_arp_requests(ip_range, cidr=24, timeout=5):
    """
    Discover active hosts in a network using ARP requests.

    :param ip_range: IP range or network in CIDR notation.
    :param cidr: Subnet mask in CIDR notation (default is 24).
    :param timeout: Timeout for ARP requests (default is 5 seconds).
    :return: A tuple containing a list of dictionaries with 'ip' and 'mac' keys for discovered hosts,
             a list of active IP addresses, and the count of discovered hosts.
    """
    def is_valid_subnet(cidr):
        try:
            cidr = int(cidr)
            return 0 <= cidr <= 32
        except ValueError:
            return False

    if not is_valid_subnet(cidr):
        return "Invalid subnet mask. Please enter a number between 0 and 32.", [], [], 0

    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = ether / arp

    hosts, active_ips = [], []

    try:
        answered, _ = srp(arp_packet, timeout=timeout, verbose=False)

        if not answered:
            return "No hosts found within the specified timeout.", hosts, active_ips, 0

        hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
        active_ips = [host['ip'] for host in hosts]  # List of active IP addresses

        # Display formatted details
        table = PrettyTable()
        table.field_names = ["IP", "MAC"]
        for host in hosts:
            table.add_row([host['ip'], host['mac']])
        print(table)

    except OSError as e:
        return f"An error occurred during ARP request: {e}", hosts, active_ips, len(hosts)

    return hosts, active_ips, len(hosts)


host_discovery_using_arp_requests("192.168.100.0",24)