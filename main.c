#include <stdio.h>
#include "args.h"
#include "dns.h"

int main(int argc, char **argv){
    args_struct args;

    if(parse_args(argc, argv, &args) != 0){
        fprintf(stderr, "Error: Argument parsing failed!\n");
        return 1;
    }

    if(args.help){
        print_help();
        return 0;
    }

    //to do
    if(args.list_interfaces){
        return 0;
    }

    if(!args.interface || !args.hostname){
        fprintf(stderr, "Error: Missing required arguments! (interface or hostname) \n");
        return 1;
    }

    dns_results result_addresses = {0};

    if(resolve_host(args.hostname, &result_addresses)){
        return 1;
    }

    for(int i = 0; i < result_addresses.count; i++){
        printf("Address #%d - %s\n", result_addresses.count, result_addresses.addrs[i]);
    }

    //to do: scan TCP ports
    if(args.tcp_ports){
        int *tcp_ports;
        int tcp_count;

        printf("TCP ports:\n");
        if(parse_ports(args.tcp_ports, &tcp_ports, &tcp_count) == 0){
            for(int i = 0; i < tcp_count; i++){
                printf("%d\n", tcp_ports[i]);
            }
        }

        //scan_tcp();
    }

    //to do: scan UDP ports
    if(args.udp_ports){
        int *udp_ports;
        int udp_count;

        printf("UDP ports:\n");
        if(parse_ports(args.udp_ports, &udp_ports, &udp_count) == 0){
            for(int i = 0; i < udp_count; i++){
                printf("%d\n", udp_ports[i]);
            }
        }
        //scan_udp();
    }

    return 0;
}