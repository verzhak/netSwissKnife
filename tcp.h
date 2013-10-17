
#ifndef MY_TCP_H
#define MY_TCP_H

#include <stdint.h>

#include <netinet/in.h>

#define CONNECT_TEST_MASK 1
#define SYN_TEST_MASK 2
#define FIN_TEST_MASK 4
#define XMASTREE_TEST_MASK 8
#define NULL_TEST_MASK 0x10

int connectTest(const in_addr_t host,uint8_t* res);
int flagsTest(const uint8_t mask,const in_addr_t host,uint8_t* res);

#endif

