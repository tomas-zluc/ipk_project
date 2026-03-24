#ifndef ARGS_H
#define ARGS_H

typedef struct{
    char *interface;
    char *hostname;
    char *tcp_ports;
    char *udp_ports;
    unsigned int timeout;
    int help;
    int list_interfaces;
}args_struct;

int parse_args(int argc, char **argv, args_struct *args);
int is_number(const char *argument);
void print_help();

#endif