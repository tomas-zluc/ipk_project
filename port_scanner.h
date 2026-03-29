#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

#define SRC_PORT 50505

struct pseudo_header {
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short ip_checksum(unsigned short *buf, int len);
unsigned short ip_checksum(unsigned short *buf, int len);
int scan_tcp_ports(int *ports, int port_count, const char *host_ip, const char *interface_ip, int timeout, const char *interface_name);
int scan_udp_ports(int *ports, int port_count, const char *host_ip, const char *interface_ip, int timeout);

#endif