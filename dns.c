#define _POSIX_C_SOURCE 200112L

#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


int resolve_host(const char *host, dns_results *results){
    struct addrinfo *addr_info_res;
    int res_status;

    //Gets the address info from provided hostname
    res_status = getaddrinfo(host, NULL, NULL, &addr_info_res);

    if(res_status){
        fprintf(stderr, "Error: DNS resolution failed. \n");
        return 1;
    }

    struct addrinfo *addr_info_tmp;
    char addr_str[MAX_ADDR_STR_LEN];

    //Goes through the linked list received from getaddrinfo and extracts all the ip addresses provided
    for(addr_info_tmp = addr_info_res; addr_info_tmp!= NULL; addr_info_tmp = addr_info_tmp->ai_next){
        int ni_ret = getnameinfo(addr_info_tmp->ai_addr, addr_info_tmp->ai_addrlen, addr_str, MAX_ADDR_STR_LEN, NULL, 0, NI_NUMERICHOST);
        if(ni_ret){
            fprintf(stderr, "ERROR: getnameinfo() failed\n");
            continue;
        }

        if(!addr_exists(results, addr_str) && results->count < MAX_ADDRS){
            strcpy(results->addrs[results->count], addr_str);
            results->count++;
        }

    }

    return 0;
}

int addr_exists(dns_results *results, const char *addr) {
    for (int i = 0; i < results->count; i++) {
        if (strcmp(results->addrs[i], addr) == 0) {
            return 1;
        }
    }
    return 0;
}