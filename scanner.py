
from scapy.all import ARP, Ether, srp
import socket
import sys
from tabulate import tabulate

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        hostname = get_hostname(received.psrc)
        devices.append({"IP Address": received.psrc, "MAC Address": received.hwsrc, "Hostname": hostname})

    return devices

if __name__ == "__main__":
    if not hasattr(sys, 'real_prefix') and sys.platform != "win32":
        import os
        if os.geteuid() != 0:
            print("This script must run as root! (sudo)")
            sys.exit(1)

    network = input("Enter your network with gateway(24 most of the time): ")  # Falls dein Netz anders ist, hier anpass
    hosts = scan_network(network)

    if hosts:
        print(tabulate(hosts, headers="keys", tablefmt="grid"))
    else:
        print("No devices found!.")
