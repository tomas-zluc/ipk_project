#ifndef DNS_H
#define DNS_H

#define MAX_ADDRS 64
#define MAX_ADDR_STR_LEN 1025

typedef struct{
    char addrs[MAX_ADDRS][MAX_ADDR_STR_LEN];
    int count;
}dns_results;

int resolve_host(const char *host, dns_results *results);
int addr_exists(dns_results *results, const char *addr);

#endif