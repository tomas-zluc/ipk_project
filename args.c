#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "args.h"

#define BASE_TIMEOUT 1000
#define MAX_PORT 65535
#define INITIAL_PORT_CAPACITY 32

int parse_args(int argc, char **argv, args_struct *args){
    memset(args, 0, sizeof(args_struct));
    args->timeout = BASE_TIMEOUT;

    for(int i = 1; i < argc; i++){

        //Help parsing
        if(strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0){
            args->help = 1;
            return 0;
        }

        //Interface parsing
        else if(strcmp(argv[i], "-i") == 0){
            if(i+1 < argc && argv[i+1][0] != '-'){
                args->interface = argv[++i];
            }
            else{
                args->list_interfaces = 1;
                return 0;
            }
        }

        //tcp ports parsing
        else if(strcmp(argv[i], "-t") == 0){
            if(i+1 >= argc || argv[i+1][0] == '-'){
                fprintf(stderr, "Error: -t requires a value! \n");
                return 1;
            }
            args->tcp_ports = argv[++i];
        }

        //udp ports parsing
        else if(strcmp(argv[i], "-u") == 0){
            if(i+1 >= argc || argv[i+1][0] == '-'){
                fprintf(stderr, "Error: -u requires a value! \n");
                return 1;
            }
            args->udp_ports = argv[++i];
        }

        //timeout parsing
        else if(strcmp(argv[i], "-w") == 0){
            if(i+1 >= argc|| argv[i+1][0] == '-'){
                fprintf(stderr, "Error: -w requires a value! \n");
                return 1;
            }

            if (!is_number(argv[i + 1])) {
                fprintf(stderr, "Error: Invalid timeout value\n");
                return 1;
            }

            args->timeout = (unsigned int)atoi(argv[++i]);
            if (args->timeout == 0) {
                fprintf(stderr, "Error: Timeout must be > 0\n");
                return 1;
            }

        }

        else{
            if(args->hostname != NULL){
                fprintf(stderr, "Error: Multiple hostnames provided!\n");
                return 1;
            }
            args->hostname = argv[i];
        }
    }

    if(!args->interface || !args->hostname){
        fprintf(stderr, "Error: Missing required arguments! (interface or hostname) \n");
        return 1;
    }
    return 0;
}

//Helper function to check if provided argument is an integer
int is_number(const char *argument) {
    if (*argument == '\0'){
        return 0;
    }

    for (int i = 0; argument[i]; i++) {
        if (argument[i] < '0' || argument[i] > '9') {
            return 0;
        }
    }
    return 1;
}


int parse_ports(const char *ports_string, int **ports, int *count){
    if(!ports_string){
        return 1;
    }

    char *copy = malloc(strlen(ports_string) + 1);
    if (!copy) {
        return 1;
    }
    strcpy(copy, ports_string);

    int capacity = INITIAL_PORT_CAPACITY;
    int *result = malloc(capacity * sizeof(int));
    if(!result){
        free(copy);
        return 1;
    }

    int n = 0;

    char *token = strtok(copy, ",");

    while(token){
        int start, end;

        //Parsing port range
        if(sscanf(token, "%d-%d", &start, &end) == 2){
            if(start>end || start <= 0 || end >= MAX_PORT){
                free(result);
                free(copy);
                return 1;
            }

            for (int p = start; p <= end; p++) {
                if (n >= capacity) {
                    capacity *= 2;
                    result = realloc(result, capacity * sizeof(int));
                }
                result[n++] = p;
            }
        }

        //Parsing singe port
        else if(sscanf(token, "%d", &start) == 1){
            if(start <= 0 || start >= MAX_PORT){
                free(result);
                free(copy);
                return 1;
            }

            if(n >= capacity){
                capacity *= 2;
                result = realloc(result, capacity * sizeof(int));
            }

            result[n++] = start;
        }
        
        else {
            free(result);
            free(copy);
            return 1;
        }

        token = strtok(NULL, ",");

    }

    *ports = result;
    *count = n;

    free(copy);
    return 0;
}

//Prints usage of this program
void print_help() {
    printf("This program is used for scanning a network for open TCP and UDP ports\n");
    printf("Usage:\n");
    printf("./ipk-L4-scan -i INTERFACE [-t PORTS] [-u PORTS] HOST [-w TIMEOUT]\n");
    printf("-i - single interface to scan\n");
    printf("-t - ports to scan for TCP. Posible to specify individual port/ports {-t 80,120,130} or port range {-t 80-130} \n"); 
    printf("-u - ports to scan for UDP. Port specification same as for TCP \n");
    printf("-w - timeout in miliseconds to wait for a response for each port \n");
    printf("HOST - hostname or IPv4/IPv6 of scanned device\n");
    printf("-h/--help - writes usage on stdout\n");
}