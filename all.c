
#include <stdint.h>

#include "error.h"
#include "all.h"

/* Подсчет контрольной суммы */
uint16_t checkSum(const uint16_t *buf, uint16_t buf_size)
{
	uint32_t sum = 0;
	
	for(;buf_size > 1; buf_size -= 2, buf ++)
		sum += *buf;
	
	if (buf_size == 1)
		sum += *((unsigned char*) buf);

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	return (~sum);
}

