from scapy.all import*
import time
import random
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp, sniff

global ip_dhcp, ip_end, ip_list
ip_dhcp = "10.0.0.16"
ip_end = 1 #Starting IP
ip_list = ["10.0.0.16", "127.0.0.1", "10.0.0.10"]

def offer(packet):
    global ip_end, ip_list
    if DHCP in packet and packet[DHCP].options[0][1] == 1: #Discover check
        print("Discover packet received")
        client_ip = "10.0.0." + str(ip_end)
        while client_ip in ip_list: #Generate IP
            print("IP: ", client_ip, "is already in use")
            ip_end += 1
            if ip_end > 254:
                print("Reached IP limit")
                client_ip = "0.0.0.0" #IP limit reached so i assign 0.0.0.0 as IP
                break
            client_ip = "10.0.0." + str(ip_end)
        offer = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                 IP(src=ip_dhcp, dst="255.255.255.255") / \
                 UDP(sport=67, dport=68) / \
                 BOOTP(op=2, yiaddr=client_ip, siaddr=ip_dhcp, giaddr="0.0.0.0", xid=packet[BOOTP].xid) / \
                 DHCP(options=[("message-type", "offer"),
                    ("subnet_mask", "255.255.255.0"),
                    ("router", "10.0.0.10"),
                    ("name_server", "127.0.0.1"),
                    ("lease_time", 3600), "end"]) ## NEED TO READ ABOUT BOOTP
        time.sleep(0.2)
        sendp(offer)
        print("Offer sent")
        sniff(filter="udp and port 68", prn=ack, count=1)

def ack(packet):
    global ip_end, ip_list
    if DHCP in packet and packet[DHCP].options[0][1] == 3:  # Request Check
        ip_list.append(packet[BOOTP].yiaddr)
        print("List of IP's: ")
        print(ip_list)
        dhcp_ack = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                   IP(src=ip_dhcp, dst="255.255.255.255") / \
                   UDP(sport=67, dport=68) / \
                   BOOTP(op=2, yiaddr=packet[BOOTP].yiaddr, siaddr=packet[BOOTP].siaddr, giaddr="0.0.0.0", xid=packet[BOOTP].xid) / \
                   DHCP(options=[("message-type", "ack"),
                                 ("subnet_mask", "255.255.255.0"),
                                 ("router", "10.0.0.18"),
                                 ("name_server", "127.0.0.1"),
                                 ("lease_time", 3600), "end"]) #ACK packet created
        time.sleep(0.2)
        sendp(dhcp_ack) #Send ACK
        print("ACK sent")

def main():
    print("DHCP server is online.")
    sniff(filter="udp and port 68", prn=offer)

if __name__ == '__main__':
    main()
