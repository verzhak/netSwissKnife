
#ifndef ERROR_H
#define ERROR_H

void printError(const unsigned short int code,const char* file, const unsigned long int line, const void* p);

#define SUCCESS 0
#define ERROR_BAD_ADDRESS 1
#define ERROR_SOCKET_CREATE 2
#define ERROR_FTOK 3
#define ERROR_SHMGET 4
#define ERROR_SHMAT 5
#define ERROR_SOCKET_SET_OPTION 6
#define ERROR_SOCKET_SET_NONBLOCK 7
#define ERROR_BAD_FLAGS_TEST 8
#define ERROR_TEST_FAIL 9
#define ERROR_MALLOC 10
#define ERROR_HOST_IS_UNREACHABLE 11
#define ERROR_LOCK 12
#define ERROR_ULOCK 13
#define ERROR_EPOLL_CREATE 14
#define ERROR_EPOLL_CTL 15
#define ERROR_FORK 16
#define ERROR_SRC_INDEFINITE 17
#define ERROR_SOCKET_CONNECT 18

#endif

