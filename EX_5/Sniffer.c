
#include <stdio.h>
#include <pcap/pcap.h>
#include <strings.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

#define MAX_PACKET 800 // as known max packet of EX2 will be less than 800
#define TIME 1000 // 1000 = 1 second
#define PROM_MODE 1 // flag

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

struct exfivepacket
{
    uint32_t unixtime;
    uint16_t length;
    uint16_t saved:3, c_flag:1, s_flag:1, t_flag:1, status:10;
    uint16_t cache;
    uint16_t padding;
};


int main(int argc, char *argv[]) {
    char filter[] = "tcp port 9999";
    struct bpf_program fp;		/* The compiled filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    char errbuf[PCAP_ERRBUF_SIZE];/* Device to sniff on *//* Error string */



// Set device
    char *dev = "lo";
    printf("Device: %s\n", dev);

// Open device for sniffing
    pcap_t *handle;  /* Session handle */

    handle = pcap_open_live(dev, BUFSIZ, PROM_MODE, TIME, errbuf); // BUFSIZ means how many bytes needed PROM_MODE on TIME in milisec
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }


    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        return(2);
    }

// Compile the filter
    if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }

// Set the filter to sniff
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return(2);
    }
    printf("test\n");

    /* Grab a packet */
    pcap_loop(handle, -1, got_packet, NULL);
    /* Print its length */
    printf("Jacked a packet with length of [%d]\n", header.len);// put in a txt file as needed
    /* Close the session */
    pcap_close(handle);
    printf("test\n");
    return 0;
}
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet) {
/* Ethernet header */
    struct ethhdr *eth_header;
    eth_header = (struct ethhdr *) packet;

/* IP Header */
    struct iphdr *ip_header;
    ip_header = (struct iphdr *) (packet + sizeof(struct ethhdr));

/* TCP Header */
    struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *) (packet + sizeof(struct ethhdr) + sizeof(struct iphdr));

/* exFivePacket */
    struct exfivepacket *app_packet;
    app_packet = (struct exfivepacket *) (packet + sizeof(struct ethhdr) + sizeof(struct iphdr) +
                                          sizeof(struct tcphdr));
    FILE *fp = fopen("315638577_203283908", "a");
    if (fp == NULL) {
        perror("Error opening file");
        return;
    }
// ETHERNET Header
    char final_src[INET_ADDRSTRLEN];
    char final_dest[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ip_header->saddr), final_src, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), final_dest, INET_ADDRSTRLEN);
    fprintf(fp, "source_ip: %s\n", final_src);
    fprintf(fp, "dest_ip: %s, source_port: %hu, dest_port: %hu, timestamp: %u total_length: %hu\n", final_dest,
            htons(tcp_header->th_sport),
            htons(tcp_header->th_dport), ntohl(app_packet->unixtime), ntohs(app_packet->length));
    fprintf(fp, "cache_flag: %hu, steps_flag: %hu, type_flag: %hu, status_code: %hu, cache_control: %hu, data:  \n",
            htons(app_packet->c_flag), htons(app_packet->s_flag), htons(app_packet->t_flag), htons(app_packet->status),
            htons(app_packet->cache));
// Print data to file
    for (int i = 0; i < MAX_PACKET; i++) {
        fprintf(fp, " %02X", (unsigned char) packet[i]);
        if (i % 16 == 0) {
            fprintf(fp, "\n");
        }
    }
    fprintf(fp,"\n\n");
    fclose(fp);

}
