#ifndef SR_CHECKSUM_H
#define SR_CHECKSUM_H
/*
 * **************************************************************************
 * Function: ip_sum_calc
 * Description: Calculate the 16 bit IP sum.
 * ***************************************************************************
 * 
 * Example code from http://www.netfor2.com/ipsum.htm
 * by alex@netfor2.com
 * */

#ifdef _LINUX_
#include <stdint.h>
#endif /* _LINUX_ */

#include <sys/types.h>
#include <arpa/inet.h>

uint16_t my_checksum(size_t bytes, uint16_t buff[]);

uint16_t ip_sum_calc(size_t len_ip_header, uint16_t buff[]);

long rfc_checksum(size_t count, uint8_t *addr);

#endif
