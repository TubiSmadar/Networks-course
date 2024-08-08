from socket import *
from scapy.all import*
import time
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether


RUDP_HEADER = 12
MAX_CHUNK = 63500
STDN_BUFFER = 1024

'''''''''''''''''''''''''''''''''
    Connect with UDP to DHCP
'''''''''''''''''''''''''''''''''

def discover():
    first = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src='0.0.0.0', dst='255.255.255.255') / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr="74:e5:f9:0c:ea:ef", xid=0x12345678) / \
                    DHCP(options=[("message-type", "discover"), "end"]) #Had a problem with xid generate i left it that way
    sendp(first)
    print("Discover sent!")
    sniff(filter="udp and port 67", prn=request, count=1)
    return dns_ip


def request(packet):
    global dns_ip
    client_ip = packet[BOOTP].yiaddr
    dns_ip = packet[DHCP].options[3][1]
    if client_ip == "0.0.0.0":
        print("IP address didn't assigned")
        return
    print ("Client IP:", client_ip)
    print("DNS:", dns_ip)
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / \
                    IP(src="0.0.0.0", dst="255.255.255.255") / \
                    UDP(sport=68, dport=67) / \
                    BOOTP(chaddr="74:e5:f9:0c:ea:ef", yiaddr=client_ip, xid=packet[BOOTP].xid) / \
                    DHCP(options=[("message-type", "request"), "end"])
    time.sleep(1)
    sendp(request)
    print("Request sent!")
    #sniff(filter="udp and port 67", count=1)


'''''''''''''''''''''''''''''''''
    Connect with UDP to DNS
'''''''''''''''''''''''''''''''''

def getDashIP(dns_ip, dns_port, app_domain):
    clientSocket = socket.socket(AF_INET, SOCK_DGRAM)
    clientSocket.bind(('localhost', 20908))
    clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverName = 'localhost'
    serverPort = 14000
    DNS_ADDRESS = (dns_ip, dns_port)

    request = DNS(rd=1, qd=DNSQR(qname=app_domain))
    clientSocket.sendto(bytes(request), DNS_ADDRESS)
    print("DNS request sent.")
    time.sleep(2)

    data, address = clientSocket.recvfrom(STDN_BUFFER)
    print("DNS response received.")

    response = DNS(data)
    app_ip = str(response.an.rdata)
    print("DASH server IP is:", app_ip)

    clientSocket.close()

    return app_ip


'''''''''''''''''''''''''''''''''
          TCP - DASH
'''''''''''''''''''''''''''''''''

def streamFromDashTCP(app_ip, app_port):
    DASH_ADDRESS = (app_ip, app_port)
    clientSocket = socket.socket(AF_INET, SOCK_STREAM)
    clientSocket.bind(('localhost', 20908))
    clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    clientSocket.connect(DASH_ADDRESS)


    # Choose picture quality to receive
    options = clientSocket.recv(STDN_BUFFER).decode()
    chosenQuality = input(options)
    while chosenQuality != "720" and chosenQuality != "480" and chosenQuality != "360":
        chosenQuality = input('Please enter a valid choice')
    clientSocket.send(chosenQuality.encode())
    
    # Receive video files
    time.sleep(1)

    frameCount = 1

    while(frameCount <= 25):
        data = b''
        while b"Finished" not in data:
            data += clientSocket.recv(STDN_BUFFER)
        data = data[:-8]

        image_copy = open(f'Copies/{frameCount}.png', "wb")
        image_copy.write(data)
        image_copy.close()
        frameCount += 1
        clientSocket.send("ACK".encode())

    print("Finished receiving video frames.")

    clientSocket.close()


def streamFromDashRUDP(app_ip, app_port):
    DASH_ADDRESS = (app_ip, app_port)
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    clientSocket.bind(('localhost', 20908))
    clientSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

    clientSocket.sendto("Please stream frames over UDP".encode(), DASH_ADDRESS)

    # Choose picture quality to receive
    options, DASH_ADDRESS = clientSocket.recvfrom(STDN_BUFFER)
    chosenQuality = input(options.decode())
    while chosenQuality != "720" and chosenQuality != "480" and chosenQuality != "360":
        chosenQuality = input('Please enter a valid choice')
    clientSocket.sendto(chosenQuality.encode(), DASH_ADDRESS)

    # Receive video files

    frameCount = 1

    while (frameCount <= 25):
        window = 4
        segments = []
        last_acked = 0
        data_seq = 0
        data = b''
        while b"Finished" not in data:
            buffer = b''
            while True:
                new_data, DASH_ADDRESS = clientSocket.recvfrom(RUDP_HEADER+MAX_CHUNK)
                if not new_data:
                    break
                buffer += new_data
            segment_header = buffer[:RUDP_HEADER].decode()
            sequence_number = int(segment_header.split(':')[2])
            print(f"Received segment {sequence_number} of frame {frameCount}")
            segments.append(sequence_number)

            if data_seq == sequence_number:
                data += buffer[12:]
                data_seq += 1
            elif data_seq < sequence_number:
                data += (('0'*8)*(sequence_number-data_seq)).encode()
                data += buffer[12:]
            else:
                data[8*(data_seq-sequence_number):] += buffer[12:]

            if sequence_number % window == 0:
                for segment in range(last_acked, sequence_number):
                    if segment not in segments:
                        clientSocket.sendto(f'NACK: {segment}'.encode(), DASH_ADDRESS)
                        break
                    elif segment == sequence_number:
                        last_acked = sequence_number
                        #clientSocket.sendto(f'ACK: {segment}'.encode(), DASH_ADDRESS

        data = data[:-8]

        image_copy = open(f'Copies/{frameCount}.png', "wb")
        image_copy.write(data)
        image_copy.close()
        print(f"Frame {frameCount} was completed")
        frameCount += 1
        clientSocket.send("ACK".encode())

    print("Finished receiving video frames.")

    clientSocket.close()


def main():
    dhcp_ip = '127.0.0.1'
    dhcp_port = 67
    dns_ip = '0.0.0.0'
    dns_port = 53
    app_ip = '0.0.0.0'
    app_port = 30577
    app_domain = "www.dashserver.com"

    dns_ip = discover()
    if dns_ip != "0.0.0.0":
        app_ip = getDashIP(dns_ip, dns_port, app_domain)
    if app_ip != "0.0.0.0":
        streamFromDashTCP(app_ip, app_port)
        streamFromDashRUDP(app_ip, app_port)
    #streamFromDashRUDP('127.0.0.1', app_port)


if __name__ == '__main__':
    main()