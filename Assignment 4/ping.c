/* Program to send ICMP Echo Requests using Raw Sockets */


#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <resolv.h>
#include <netdb.h>

#define ICMP_HDRLEN 8

unsigned short calculate_checksum(unsigned short *paddress, int len);



int main(int argc, char *strings[]) {
    if(argc != 2) {
        printf("usage: %s <addr>\n", strings[0]);
        exit(0);
    }
    
    printf("hello parta\n");

    struct hostent *hname;
    hname = gethostbyname(strings[1]);

    struct sockaddr_in destAddr;
    bzero(&destAddr, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;
    destAddr.sin_addr.s_addr = *(long*)hname->h_addr;
    
    int mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(mySocket < 0){
        perror("socket");
        return -1;
    }

    int ttl = 255;
    int sockopt = setsockopt(mySocket, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    if (sockopt != 0){
            perror("setsockopt");
            return -1;
        }

    char data[IP_MAXPACKET] = "This is the ping.\n";
    int datalen = strlen(data) + 1;

    char packet[IP_MAXPACKET];

    struct timeval start, end;

    int packetSeq = 0;

    while(1) {
   
        struct icmp icmphdr; // ICMP-header
        icmphdr.icmp_type = ICMP_ECHO;
        icmphdr.icmp_code = 0;
        icmphdr.icmp_id = 18;
        icmphdr.icmp_seq = packetSeq++;
        icmphdr.icmp_cksum = 0;

        bzero(packet, IP_MAXPACKET);
        memcpy((packet), &icmphdr, ICMP_HDRLEN);
        memcpy(packet + ICMP_HDRLEN, data, datalen);
        icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
        memcpy((packet), &icmphdr, ICMP_HDRLEN);

        gettimeofday(&start, 0);

        // Send the packet using sendto() for sending datagrams.
        int bytesSent = sendto(mySocket, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&destAddr, sizeof(destAddr));
        if (bytesSent == -1) {
            perror("sendto");
            return -1;
        }
        //printf("Successfuly sent one packet : ICMP HEADER : %d bytes, data length : %d , icmp header : %d \n", bytesSent, datalen, ICMP_HDRLEN);

        // Get the ping response
        bzero(packet, IP_MAXPACKET);
        socklen_t len = sizeof(destAddr);
        ssize_t bytesReceived = -1;
        while ((bytesReceived = recvfrom(mySocket, packet, sizeof(packet), 0, (struct sockaddr *)&destAddr, &len))) {
            if (bytesReceived > 0) {
                gettimeofday(&end, 0);

                // Check the IP header
                //struct iphdr *iphdr = (struct iphdr *)packet;
                //struct icmphdr *icmphdr = (struct icmphdr *)(packet + (iphdr->ihl * 4));
                float RTT = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;

                printf("Ping returned: %ld bytes from IP = %s, Seq = %d, RTT = %.3f milliseconds\n", bytesReceived, strings[1], packetSeq, RTT);
                break;
            }
        }
        sleep(1);
    }
    // Close the raw socket descriptor.
    close(mySocket);

    return 0;
}

// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    for(; len > 1; len -= 2){
        sum += *w++;
    }
    if(len == 1){
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}
