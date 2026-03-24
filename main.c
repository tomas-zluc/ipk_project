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
        //scan_tcp();
    }

    //to do: scan UDP ports
    if(args.udp_ports){
        //scan_udp();
    }

    return 0;
}