
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "error.h"
#include "all.h"
#include "operation.h"

void help(void);

int main(const int argc,const char* argv[])
{
	unsigned char is_scan = 1;
	VERBOSE = 0;
	NUM_PORT = 1024;
	DURATION = 5;
	CONNECT_TCP_TEST_ENABLE = 1;
	ONLY_FIRST_ADDRESS_SCAN = 1;

	int c;
	for(c = 1; c < argc; c++)
		if(!strcmp(argv[c],"-h") || !strcmp(argv[c],"--help"))
			help();
		else if (!strcmp(argv[c],"-a") || !strcmp(argv[c],"--all-ports"))
		{
			NUM_PORT = 65535;
			DURATION = 90;
		}
		else if (!strcmp(argv[c],"-r") || !strcmp(argv[c],"--privileged-ports"))
		{
			NUM_PORT = 1024;
			DURATION = 5;
		}
		else if (!strcmp(argv[c],"-p") || !strcmp(argv[c],"--ping"))
			is_scan = 0;
		else if (!strcmp(argv[c],"-s") || !strcmp(argv[c],"--scan"))
			is_scan = 1;
		else if (!strcmp(argv[c],"-v") || !strcmp(argv[c],"--verbose"))
			VERBOSE = 1;
		else if (!strcmp(argv[c],"-n") || !strcmp(argv[c],"--no-verbose"))
			VERBOSE = 0;
		else if (!strcmp(argv[c],"-f") || !strcmp(argv[c],"--first-addr"))
			ONLY_FIRST_ADDRESS_SCAN = 1;
		else if (!strcmp(argv[c],"-l") || !strcmp(argv[c],"--all-addr"))
			ONLY_FIRST_ADDRESS_SCAN = 0;
		else if (!strcmp(argv[c],"--connect-test"))
			CONNECT_TCP_TEST_ENABLE = 1;
		else if (!strcmp(argv[c],"--d-connect-test"))
			CONNECT_TCP_TEST_ENABLE = 0;
		else
		{
			struct addrinfo *res;
			struct addrinfo *hint = NULL;

			if(is_scan)
			{
				hint = (struct addrinfo*) malloc(sizeof(struct addrinfo));

				hint->ai_family = AF_INET;
				hint->ai_socktype = 0;
				hint->ai_protocol = IPPROTO_TCP;
				hint->ai_flags = AI_V4MAPPED | AI_ADDRCONFIG; /* Default */
			}
			
			int ai = getaddrinfo(argv[c],NULL,hint,&res);

			if(is_scan)
				free(hint);

			if(ai)
				printError(ERROR_BAD_ADDRESS,__FILE__,__LINE__,(void*)argv[c]);
			else
			{
				if(is_scan)
				{
					struct addrinfo* next = res;
					if(ONLY_FIRST_ADDRESS_SCAN)
						scan_tcp(((struct sockaddr_in*)next->ai_addr)->sin_addr.s_addr);
					else
						for(;next != NULL; next = next->ai_next)
							scan_tcp(((struct sockaddr_in*)next->ai_addr)->sin_addr.s_addr);
				}
				else
					ping(((struct sockaddr_in*)res->ai_addr)->sin_addr.s_addr);

				freeaddrinfo(res);
			}
		}
	return 0;
}

void help(void)
{
	printf("#####################################\n\
Network Swiss Knife\n\
Author: Maxim Akinin (verzhak@gmail.com)\n\
Version: %s (TCP-scanner, ICMP-ping utility)\n\
Date: %s\n\
This is free software (GPLv3). There is NO warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE\n\n\
Run: netSwissKnife ARGUMENTS\n\n\
Arguments:\n\
\t-h --help\t\t-\tprint this message\n\
\t-r --privileged-ports\t-\tscan ports 1 - 1024 (replace --all-ports; default)\n\
\t-a --all-ports\t\t-\tscan ports 1 - 65535 (too slow) (replace --privileged-ports)\n\
\t-s --scan\t\t-\tscan hosts (replace --ping; default)\n\
\t-p --ping\t\t-\tping hosts (replace --scan)\n\
\t--connect-test\t\t-\tenable connect tcp test (replace --d-connect-test; default)\n\
\t--d-connect-test\t-\tdisable connect tcp test (replace --connect-test)\n\
\t-f --first-addr\t\t-\tscan first IP-address of host (replace --all-addr; default)\n\
\t-l --all-addr\t\t-\tscan all IP-addresses of host (replace --first-addr)\n\
\t-n --no-verbose\t\t-\tprint only results (replace --verbose; default)\n\
\t-v --verbose\t\t-\tmore information about scanning (replace --no-verbose)\n\
\tADDRESS\t\t\t-\tstart scanning ADDRESS (may be symbolic or IPv4)\n\n\
Enjoy!\n\
#####################################\n\
", VERSION,DATE);
}

