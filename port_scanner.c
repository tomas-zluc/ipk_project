#include "port_scanner.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>

int scan_tcp_ports(int *ports, int port_count, const char *ip, int timeout){
    for(int i = 0; i < port_count; i++){
    }
    return 0;
}

int scan_udp_ports(int *ports, int port_count, const char *ip, int timeout){
    for(int i = 0; i < port_count; i++){
    }
    return 0;
}

