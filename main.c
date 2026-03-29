#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "args.h"
#include "dns.h"
#include "port_scanner.h"

int main(int argc, char **argv){
    args_struct args;

    //Checks, if arguments were passed correctly
    if(parse_args(argc, argv, &args) != 0){
        fprintf(stderr, "Error: Argument parsing failed!\n");
        return 1;
    }

    //if help flag was present, prints help and exits
    if(args.help){
        print_help();
        return 0;
    }
    
    //to do
    if(args.list_interfaces){
        list_interfaces();
        return 0;
    }

    //DNS resolution - stores IP addresses dns_results structure 
    dns_results result_addresses = {0};
    if(resolve_host(args.hostname, &result_addresses)){
        return 1;
    }

    //Interface IP resolution
    char source_ip[INET_ADDRSTRLEN];
    if(resolve_interface(args.interface, source_ip) != 0){
        fprintf(stderr, "Error: Could not get IP of interface %s\n", args.interface);
        return 1;
    }

    if(args.tcp_ports){
        int *tcp_ports;
        int tcp_count;

        if(parse_ports(args.tcp_ports, &tcp_ports, &tcp_count) != 0){
            fprintf(stderr, "Error: Parsing TCP ports unsuccessful.\n");
            free(tcp_ports);
            return 1;
        }

        for(int i = 0; i < result_addresses.count; i++){
            scan_tcp_ports(tcp_ports, tcp_count, result_addresses.addrs[i], source_ip, args.timeout, args.interface);
        }

        free(tcp_ports);
    }

    if(args.udp_ports){
        int *udp_ports;
        int udp_count;

        if(parse_ports(args.udp_ports, &udp_ports, &udp_count) != 0){
            fprintf(stderr, "Error: Parsing UDP ports unsuccessful.\n");
            free(udp_ports);
            return 1;
        }

        for(int i = 0; i < result_addresses.count; i++){
            scan_udp_ports(udp_ports, udp_count, result_addresses.addrs[i], source_ip, args.timeout);
        }

        free(udp_ports);

    }

    return 0;
}