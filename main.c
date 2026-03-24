#include <stdio.h>
#include "args.h"

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