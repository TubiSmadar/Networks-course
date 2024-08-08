//
// Created by yair on 1/19/23.
//
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <pcap/pcap.h>

/* IP header */
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};

/* ICMP Header  */
struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int id;     //Used for identifying request
    unsigned short int seq;   //Sequence number
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);
unsigned short calculate_checksum(unsigned short *paddress, int len);
void send_raw_ip_packet(struct ipheader* ip);

int main(){
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "icmp and icmp[0] = 8";
    bpf_u_int32 net;


    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("br-5a8167b262bd", BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        perror("handle problem");
        exit(1);
    }

    // Step 2: Compile filter_exp into BPF
    int pcap = pcap_compile(handle, &fp, filter_exp, 0, net);
    if(pcap < 0){
        perror("pcap compiling problem");

        exit(1);
    }

    pcap_setfilter(handle, &fp);

    // Step 3: Capture packets

    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    struct ipheader *ip_header = (struct ipheader *)(packet + sizeof(struct ethhdr));
    struct icmpheader *icmp_header = (struct icmpheader *)(packet + sizeof(struct ethhdr) + sizeof(struct ipheader));
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET,&(ip_header->iph_sourceip),src_ip,INET_ADDRSTRLEN);
    inet_ntop(AF_INET,&(ip_header->iph_destip),dest_ip,INET_ADDRSTRLEN);

    // Sniffed packet details
    printf("Sniffed packet details\n");
    printf("source_ip: %s",inet_ntoa(ip_header->iph_sourceip));
    printf(", dest_ip: %s\n",inet_ntoa(ip_header->iph_destip));

    if( icmp_header->icmp_type == 8) //8 == request
    {
        char spoof[1500];
        memset((char *)spoof, 0, 1500);
        //memcpy((char *)spoof, ip_header, ntohs(ip_header->iph_len)); //uncomment this line to make the
        struct ipheader *ipheader = (struct ipheader *)(spoof+sizeof(struct ethhdr));
        struct icmpheader *icmpheader = (struct icmpheader *) (spoof + sizeof(struct ethhdr) + sizeof(struct ipheader));

        ipheader->iph_ver = 4;
        ipheader->iph_ihl = 5;
        ipheader->iph_ttl = 20;

        ipheader->iph_sourceip = ip_header->iph_destip;
        ipheader->iph_destip = ip_header->iph_sourceip;

        ipheader->iph_protocol = IPPROTO_ICMP;
        ipheader->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

        icmpheader->icmp_type = 0;//0 == reply
        icmpheader->icmp_chksum =0;
        icmpheader->icmp_chksum= calculate_checksum((unsigned short *)icmpheader, sizeof(struct icmpheader));

        printf("Spoofed packet details*********\n");
        printf("source_ip: %s",inet_ntoa(ipheader->iph_sourceip));
        printf(", dest_ip: %s\n",inet_ntoa(ipheader->iph_destip));
       // printf("whatappp\n");
        send_raw_ip_packet(ipheader);

    }
}
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

void send_raw_ip_packet(struct ipheader* ip){
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    int set = setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));
    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;
    // Step 4: Send the packet out.
    int sent = sendto(sock, ip, ntohs(ip->iph_len), 0,
           (struct sockaddr *)&dest_info, sizeof(dest_info));
    if (sent == -1) {
        printf("Send error\n");
    }

    close(sock);
}
