
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "all.h"
#include "error.h"

void printError(const unsigned short int code,const char* file, const unsigned long int line, const void* p)
{
	fprintf(stderr,"[ERROR: ");
	switch (code)
	{
		case SUCCESS:
			{
				fprintf(stderr,"Success");
				break;
			}
		case ERROR_BAD_ADDRESS:
			{
				fprintf(stderr,"Bad address %s",(char*)p);
				break;
			}
		case ERROR_SOCKET_CREATE:
			{
				fprintf(stderr,"Socket create fail");
				break;
			}
		case ERROR_FTOK:
			{
				fprintf(stderr,"Get IPC-key fail");
				break;
			}
		case ERROR_SHMGET:
			{
				fprintf(stderr,"Shared memory allocation fail (shmget)");
				break;
			}
		case ERROR_SHMAT:
			{
				fprintf(stderr,"Shared memory allocation fail (shmat)");
				break;
			}
		case ERROR_SOCKET_SET_OPTION:
			{
				fprintf(stderr,"Set socket option fail");
				break;
			}
		case ERROR_SOCKET_SET_NONBLOCK:
			{
				fprintf(stderr,"Set socket nonblock fail");
				break;
			}
		case ERROR_BAD_FLAGS_TEST:
			{
				fprintf(stderr,"Bad flag test [mask: %u]",*(uint8_t*)p);
				break;
			}
		case ERROR_TEST_FAIL:
			{
				fprintf(stderr,"%s test fail",(char*)p);
				break;
			}
		case ERROR_MALLOC:
			{
				fprintf(stderr,"Memory allocated error");
				break;
			}
		case ERROR_HOST_IS_UNREACHABLE:
			{
				fprintf(stderr,"Host %s is unreachable",(char*)p);
				break;
			}
		case ERROR_SRC_INDEFINITE:
			{
				fprintf(stderr,"Source ip-addresses is indefinite [destination host: %s]",(char*)p);
				break;
			}
		case ERROR_LOCK:
			{
				fprintf(stderr,"Socket lock fail");
				break;
			}
		case ERROR_ULOCK:
			{
				fprintf(stderr,"Socket unlock fail");
				break;
			}
		case ERROR_EPOLL_CREATE:
			{
				fprintf(stderr,"epoll create fail");
				break;
			}
		case ERROR_EPOLL_CTL:
			{
				fprintf(stderr,"epoll ctl fail");
				break;
			}
		case ERROR_FORK:
			{
				fprintf(stderr,"Fork fail");
				break;
			}
		case ERROR_SOCKET_CONNECT:
			{
				fprintf(stderr,"Connect fail");
				break;
			}
		default:
				fprintf(stderr,"Unknown error");
	}
	
	if(VERBOSE)
		fprintf(stderr," (%s) (version: %s, file: %s, line: %lu)",strerror(errno),
				VERSION,file,line);

	fprintf(stderr,"]\n");
}

