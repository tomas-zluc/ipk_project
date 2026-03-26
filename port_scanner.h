#ifndef PORT_SCANNER_H
#define PORT_SCANNER_H

int scan_tcp_ports(int *ports, int port_count, const char *ip, int timeout);
int scan_udp_ports(int *ports, int port_count, const char *ip, int timeout);

#endif