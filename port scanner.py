import socket
import scapy.all as scapy

def scan_ports(target_ip, ports):
    print(f"Scanning {target_ip} for open ports...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            print(f"[+] Port {port} is open")
        sock.close()

def network_scan(ip_range):
    print(f"Scanning network {ip_range} for active devices...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print("IP Address\t\tMAC Address")
    print("--------------------------------------")
    for element in answered_list:
        print(f"{element[1].psrc}\t{element[1].hwsrc}")

if __name__ == "__main__":
    target_ip = input("Enter target IP to scan ports: ")
    port_range = range(20, 1025)  
    scan_ports(target_ip, port_range)
    
    ip_range = input("Enter network IP range (e.g., 192.168.1.1/24): ")
    network_scan(ip_range)
