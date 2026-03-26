#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>


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

int resolve_interface(const char *if_name, char *ip_buffer){
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        if (!ifa->ifa_addr){
            continue;
        }

        if (strcmp(ifa->ifa_name, if_name) != 0){
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, ip_buffer, INET_ADDRSTRLEN);
            freeifaddrs(ifaddr);
            return 0;
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

int list_interfaces() {
    struct ifaddrs *ifaddr, *ifa;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {

        if (!ifa->ifa_name || !ifa->ifa_addr){
            continue;
        }

        if (!(ifa->ifa_flags & IFF_UP)){
            continue;
        }

        //avoiding duplicates
        int printed = 0;
        for (struct ifaddrs *tmp = ifaddr; tmp != ifa; tmp = tmp->ifa_next) {
            if (tmp->ifa_name && strcmp(tmp->ifa_name, ifa->ifa_name) == 0) {
                printed = 1;
                break;
            }
        }

        if (!printed) {
            printf("%s\n", ifa->ifa_name);
        }
    }

    freeifaddrs(ifaddr);
    return 0;
}