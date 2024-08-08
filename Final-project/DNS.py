from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from socket import *
import time

app_domain = 'www.dashserver.com'
dns_ip = '127.0.0.1'

def DNS_Reply():
    dnsQuery, clientAddress = dns_socket.recvfrom(2048)
    print("Got request from client.")

    # DNS query to respond to
    query = DNS(rd=1, qd=DNSQR(qname=app_domain))

    # DNS response
    response = DNSRR(rrname=app_domain, type="A", ttl=60, rdata="127.0.0.1")
    dns_pack = DNS(id=query.id, ancount=1, qr=1, qd=query.qd, an=response)

    dns_socket.sendto(bytes(dns_pack), clientAddress)
    
    print("Sent response.")
    time.sleep(1)

if __name__ == '__main__':
    dns_port = 53
    SERVER_ADDRESS = ('localhost', dns_port)
    dns_socket = socket(AF_INET, SOCK_DGRAM)
    dns_socket.bind(SERVER_ADDRESS)
    print("The DNS server is ready to receive requests.")
    while True:
        DNS_Reply()
    dns_socket.close()