from scapy.all import IP, ICMP, sr1, TCP

def detect_os(target):
    try:
        pkt = IP(dst=target) / ICMP()
        resp = sr1(pkt, timeout=3)

        if resp and IP in resp:
            ttl = resp.getlayer(IP).ttl
            tcp_window_size = None

            if TCP in resp:
                tcp_window_size = resp.getlayer(TCP).window

            if ttl == 64 and tcp_window_size == 5840:
                return 'Linux'
            elif ttl == 64 and tcp_window_size == 5270:
                return 'Google\'s Customized Linux'
            elif ttl == 64 and tcp_window_size == 65535:
                return 'FreeBSD'
            elif ttl == 128 and tcp_window_size == 65535:
                return 'Windows XP'
            elif ttl == 128 and tcp_window_size == 8192:
                return 'Windows Server 2008 or Windows 7'
            elif ttl == 255 and tcp_window_size == 4128:
                return 'Cisco Router (IOS 12.4)'
            else:
                return 'Unknown OS'
        else:
            return 'Not Found'

    except Exception as e:
        print(f"An error occurred: {e}")
        return 'Not Found'

def main():
    target_ip = input("Enter the IP address: ")
    detected_os = detect_os(target_ip)

    if detected_os != 'Not Found':
        print(f"Detected OS: {detected_os}")
    else:
        print("OS detection failed.")

if __name__ == "__main__":
    main()
