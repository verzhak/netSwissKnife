
#ifndef MY_ICMP_H
#define MY_ICMP_H

#include <stdint.h>

#include <netinet/in.h>

uint8_t ping_icmp(const in_addr_t host);

#endif

