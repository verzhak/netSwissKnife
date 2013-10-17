
#ifndef OPERATION_H
#define OPERATION_H

#include <netinet/in.h>

void scan_tcp(const in_addr_t host);
void ping(const in_addr_t host);

#endif

