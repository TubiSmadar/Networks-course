/* Program to send ICMP Echo Requests using Raw Sockets, using a Watchdog Timer. */


/* Included Libraries */
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
#define WATCHDOG_IP "127.0.0.1"
#define WATCHDOG_PORT 3000

unsigned short calculate_checksum(unsigned short *paddress, int len);

int main(int argc, char *strings[]) {
    
    // Verify the program was run correctly
    if(argc != 2) {
        printf("usage: %s <addr>\n", strings[0]);
        exit(0);
    }
    
    // Create TCP socket
    int tcpSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpSocket == -1){
        printf("Socket not created: %d\n", errno);
    }

    // Struct Watchdog's internet address
    struct sockaddr_in wdAddress;
    memset(&wdAddress, 0, sizeof(wdAddress));
    wdAddress.sin_family = AF_INET;
    wdAddress.sin_port = htons(WATCHDOG_PORT);
    int ip_addr = inet_pton(AF_INET, (const char *)WATCHDOG_IP, &wdAddress.sin_addr);
    if (ip_addr < 1){
        ip_addr == -1 ? printf("inet_pton() failed %d: ", errno) : printf("inet_pton() src invalid");
    }

    // Struct the internet address of the destination IP
    struct hostent *hname;
    hname = gethostbyname(strings[1]);

    struct sockaddr_in destAddr;
    bzero(&destAddr, sizeof(destAddr));
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = 0;
    destAddr.sin_addr.s_addr = *(long*)hname->h_addr;

    // Create Raw Socket for sending ICMP Echo Requests        
    int rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(rawSocket < 0){
        perror("socket");
        return -1;
    }

    // Set ttl for all packets sent through Raw Socket        
    int ttl = 255;
    int sockopt = setsockopt(rawSocket, SOL_IP, IP_TTL, &ttl, sizeof(ttl));
    if (sockopt != 0){
        perror("setsockopt");
        return -1;
    }

/*--------------------------------------------------------------------*/
/*---           Run Watchdog program as child process              ---*/
/*--------------------------------------------------------------------*/    
    char *args[2];
    args[0] = "./watchdog";
    args[1] = NULL;
    int pid = fork();

    if (pid == 0) {
        printf("In child\n");
        printf("Running watchdog...\n");
        execvp(args[0], args);
    } else {
        sleep(2);

/*--------------------------------------------------------------------*/
/*---  Run main process (with 1 second delay for good connection)  ---*/
/*--------------------------------------------------------------------*/          

        // Establish TCP connection with Watchdog   
        int connectionStatus = connect(tcpSocket, (struct sockaddr *)&wdAddress, sizeof(wdAddress));
        if (connectionStatus == -1){
            printf("Socket not connected: %d", errno);
        } else {
            printf("connected to Watchdog\n");
        }
        
        // Receive "ready signal" from watchdog
        int wdReady = 0;
        while(!wdReady) {
            recv(tcpSocket, &wdReady, 1, 0);
        }

        // Send Watchdog the destIP address
        send(tcpSocket, strings[1], 16, 0);

        // Variables for main while-loop 
        char data[IP_MAXPACKET] = "Ping.\n";
        int datalen = strlen(data) + 1;
        char packet[IP_MAXPACKET];
        int packetSeq = 0;

        struct timeval start, end;

        char pingStatus[5];

/*--------------------------------------------------------------------*/
/*---                       Main while-loop                        ---*/
/*--------------------------------------------------------------------*/       
        while(1) {

            // Assemble ping packet
            struct icmp icmphdr;
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

            // Send ping
            gettimeofday(&start, 0);
            sendto(rawSocket, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)&destAddr, sizeof(destAddr));

            // Notify Watchdog that ping has been sent
            strcpy(pingStatus, "ping");
            send(tcpSocket, pingStatus, sizeof(pingStatus), 0);

            printf("Waiting for ICMP Echo Response...\n");
            bzero(packet, IP_MAXPACKET);

            // Fork receive - timeout from watchdog or pong from destIP 
            int replyPID = fork();
            
            /*--- Watchdog timeout ---*/
            if(replyPID == 0){
                recv(tcpSocket, &packet, sizeof(packet), 0);
                if (strcmp("Timeout", packet) == 0){
                    printf("Received timeout.\n");
                    int myPid = getppid();
                    kill(myPid, SIGTERM);
                    exit(0);
                }

            /*--- Receive ping response ---*/
            } else {
                socklen_t len = sizeof(destAddr);
                int bytesReceived = recvfrom(rawSocket, packet, sizeof(packet), 0, (struct sockaddr *)&destAddr, &len);
                if (bytesReceived > 0) {
                    gettimeofday(&end, 0);

                    // Notify Watchdog that ping was received
                    strcpy(pingStatus, "pong");
                    send(tcpSocket, pingStatus, sizeof(pingStatus), 0);
                    
                    // Print out ping data
                    float RTT = (end.tv_sec - start.tv_sec) * 1000.0f + (end.tv_usec - start.tv_usec) / 1000.0f;
                    printf("Ping returned: %d bytes from IP = %s, Seq = %d, RTT = %.3f milliseconds\n", bytesReceived, strings[1], packetSeq, RTT);
                    sleep(1);
                }
            }
        }
        close(tcpSocket);
        close(rawSocket);
    }
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