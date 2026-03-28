#include "port_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap/pcap.h>

unsigned short ip_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;

    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }

    if (len)
        sum += *(unsigned char *)buf;

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

unsigned short tcp_checksum(struct iphdr *ip_header, struct tcphdr *tcp_header) {

    struct pseudo_header psh;

    psh.src_addr = ip_header->saddr;
    psh.dst_addr = ip_header->daddr;
    psh.zero = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);

    char *pseudogram = malloc(psize);
    if (!pseudogram) {
        return 0;
    }

    memcpy(pseudogram, &psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header),
           tcp_header,
           sizeof(struct tcphdr));

    unsigned short result = ip_checksum((unsigned short*)pseudogram, psize);

    free(pseudogram);
    return result;
}

int scan_tcp_ports(int *ports, int port_count, const char *host_ip, const char *interface_ip, int timeout){

    //Only for now - gets rid of IPv6
    int is_ipv6 = strchr(host_ip, ':') != NULL;
    if(is_ipv6){
        return 0;
    }

    //Create raw socket
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(raw_sock < 0){
        perror("socket");
        return 1;
    }

    //Set options for the socket
    int one = 1;
    if(setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0){
        fprintf(stderr, "ERROR: Problem with setting socket options.\n");
        return 1;
    }

    //Convert the IP from string to a binary form
    struct sockaddr_in target;
    memset(&target, 0, sizeof(target));
    target.sin_family = AF_INET;

    if(inet_pton(AF_INET, host_ip, &target.sin_addr) != 1){
        fprintf(stderr, "ERROR: Invalid IPv4 address %s\n", host_ip);
        close(raw_sock);
        return 1;
    }

    //Create packet
    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));

    //Fill in IP header
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = htons(10); //Random arbitrary number - must be filled, but doesn´t play any role while sending single packet
    ip_header->frag_off = 0;
    ip_header->ttl = 64;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->saddr = inet_addr(interface_ip);
    ip_header->daddr = target.sin_addr.s_addr;
    ip_header->check = 0; //Has to be set to 0, for the checksum calculation to work properly
    ip_header->check = ip_checksum((unsigned short *)ip_header, sizeof(struct iphdr));

    //Fill in TCP header
    tcp_header->source = htons(SRC_PORT);
    tcp_header->seq = htonl(0);
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->syn = 1;
    tcp_header->ack = 0;
    tcp_header->fin = 0;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(65535);
    tcp_header->urg_ptr = 0;
    tcp_header->check = 0; //Same with IP, has to be filled with 0 before calculating checksum

    for(int i = 0; i < port_count; i++){
        tcp_header->dest = htons(ports[i]);
        tcp_header->check = tcp_checksum(ip_header, tcp_header);
        if(sendto(raw_sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&target, sizeof(target)) < 0){
            fprintf(stderr, "Error: Problem with sending TCP packet. \n");
            close(raw_sock);
            return 1;
        }
        printf("Scanning port %d for TCP socket from interface %s on host %s with %dms timeout\n", ports[i], interface_ip, host_ip, timeout);
    }

    close(raw_sock);
    return 0;
}

int scan_udp_ports(int *ports, int port_count, const char *host_ip, const char *interface_ip, int timeout){
    for(int i = 0; i < port_count; i++){
        printf("Scanning port %d for UDP socket from interface %s on host %s with %dms timeout\n", ports[i], interface_ip, host_ip, timeout);
    }
    return 0;
}