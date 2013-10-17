
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "error.h"
#include "operation.h"
#include "all.h"
#include "tcp.h"
#include "icmp.h"

/* Система нечеткого вывода (Мамдани-Заде) для анализа результата тестирования tcp-порта */
unsigned char analysis_tcp(uint8_t prec_x)
{
	uint8_t x[5],prec_y;
	float u[5],y;

	/* Фуззификатор */

	x[0] = prec_x & CONNECT_TEST_MASK;
	x[1] = prec_x & SYN_TEST_MASK;
	x[2] = prec_x & FIN_TEST_MASK;
	x[3] = prec_x & XMASTREE_TEST_MASK;
	x[4] = prec_x & NULL_TEST_MASK;

	/* Система вывода */

	if (x[0])
		u[0] = 1;
	else
		u[0] = 0.1;

	if (x[1])
		u[1] = 1;
	else
		u[1] = 0.3;

	if (x[2])
		u[2] = 0.5;
	else
		u[2] = 0;

	if (x[3])
		u[3] = 0.5;
	else
		u[3] = 0;

	if (x[4])
		u[4] = 0.5;
	else
		u[4] = 0;

	/* Агрегатор */

	if ((u[0] == 1) || (u[1] == 1))
		y = 1;
	else if (!((u[2] == 0) && (u[3] == 0) && (u[4] == 0)))
		y = 0;
	else
		y = (u[0] + u[1] + u[2] + u[3] + u[4]) / 5;

	/* Дефузификатор
	 * prec_y == 2 -> "Порт открыт"
	 * prec_y == 1 -> "Порт, возможно, открыт"
	 * prec_y == 0 -> "Порт закрыт" */

	if (y == 1)
		prec_y = 2;
	else if (y >= 0.5)
		prec_y = 1;
	else
		prec_y = 0;

	return prec_y;
}

/* Сканирование tcp-портов */
void scan_tcp(const in_addr_t host)
{
	struct in_addr dest;
	dest.s_addr = host;

	uint8_t *scan_res = (unsigned char*)malloc(NUM_PORT);
	if(scan_res == NULL)
	{
		printError(ERROR_MALLOC,__FILE__,__LINE__,NULL);
		return;
	}

	memset((void*)scan_res,0,NUM_PORT);

	printf("%s\nTCP-scan (Connect, Syn, Fin, Xmas Tree, NULL): %s\n",SUGAR_STRING,inet_ntoa(dest));

	if(CONNECT_TCP_TEST_ENABLE)
	{
		if(connectTest(host,scan_res) < 0)
			printError(ERROR_TEST_FAIL,__FILE__,__LINE__,(void*) "Connect");
		if(VERBOSE)
			printf("Connect test done\n");
	}
	else
		printf("Connect test disable (enable it by --connect-test)\n");

	if(flagsTest(SYN_TEST_MASK,host,scan_res) < 0)
		printError(ERROR_TEST_FAIL,__FILE__,__LINE__,(void*) "Syn");
	if(VERBOSE)
		printf("Syn test done\n");
	
	if(flagsTest(FIN_TEST_MASK,host,scan_res) < 0)
		printError(ERROR_TEST_FAIL,__FILE__,__LINE__,(void*) "Fin");
	if(VERBOSE)
		printf("Fin test done\n");
	
	if(flagsTest(XMASTREE_TEST_MASK,host,scan_res) < 0)
		printError(ERROR_TEST_FAIL,__FILE__,__LINE__,(void*) "Xmas Tree");
	if(VERBOSE)
		printf("Xmas Tree test done\n");
	
	if(flagsTest(NULL_TEST_MASK,host,scan_res) < 0)
		printError(ERROR_TEST_FAIL,__FILE__,__LINE__,(void*) "NULL");
	if(VERBOSE)
		printf("NULL test done\n");

	uint32_t port;
	unsigned char analysis_res;

	for(port = 0 ; port < NUM_PORT; port++)
	{
		analysis_res = analysis_tcp(scan_res[port]);

		if((VERBOSE && scan_res[port]) || (!VERBOSE && analysis_res))
		{
			printf("%d",port + 1);
			
			if(VERBOSE)
			{
				printf("\t[");
				if(scan_res[port] & CONNECT_TEST_MASK)
					printf(" Connect");
				if(scan_res[port] & SYN_TEST_MASK)
					printf(" Syn");
				if(scan_res[port] & FIN_TEST_MASK)
					printf(" Fin");
				if(scan_res[port] & XMASTREE_TEST_MASK)
					printf(" XmasTree");
				if(scan_res[port] & NULL_TEST_MASK)
					printf(" NULL");
				printf(" ]");
			}

			switch (analysis_res)
			{
				case 2:
				{
					printf("\t[ open ]\n");
					break;
				}
				case 1:
				{
					printf("\t[ maybe open ]\n");
					break;
				}
				default:
				{
					printf("\n");
					break;
				}
			}
		}
	}

	printf("%s\n",SUGAR_STRING);

	free(scan_res);
}

/* Пинг (с помощью icmp-echo и icmp-echo-reply пакетов) */
void ping(const in_addr_t host)
{
	struct in_addr host_in_addr;

	host_in_addr.s_addr = host;

	printf("%s\nPing (icmp): %s\n",SUGAR_STRING,inet_ntoa(host_in_addr));

	uint8_t return_packages = ping_icmp(host);

	if(return_packages == 0)
		printf("[ !!! Host is unreachable !!! ]\n");

	printf("Send: %u packages\tReturn: %u packages (%.2f%%)\n%s\n",NUM_PING_PACKAGES,return_packages,(return_packages / (float) NUM_PING_PACKAGES) * 100.0,SUGAR_STRING);
}

