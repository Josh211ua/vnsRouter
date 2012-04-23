/* Joshua Smith
 * josh211ua@gmail.com
 *
 *
 */

#include "sr_checksum.h"
#include <stdio.h>
/*
int main(void) 
{
    uint16_t buf[] = { 0x4500, 0x0073, 0x0000, 0x4000,
                      0x4011, 0x0000, 0xc0a8, 0x0001,
                      0xc0a8, 0x00c7 };

    uint16_t buf2[] = { 0x4500, 0x0054, 0x16d8, 0x0000,
                      0xff01, 0x0000, 0xab43, 0xf240,
                      0x80dc, 0xe075 };

    uint16_t checksum = my_checksum(10, buf2);
    printf("Checksum: %x\n", checksum);
    printf("Expected: %x\n", 0xa5fa);
    return 0;
}
*/

uint16_t my_checksum(size_t bytepairs, uint16_t buf[])
{
    uint32_t sum = 0;
    for(int i = 0; i < bytepairs; i++) {
        sum += buf[i];
    }

    printf("Sum: %x\n", sum);
    uint16_t top = sum >> 16;
    uint16_t bottom = sum & 0xffff;
    printf("Top: %x\n", top);
    printf("Bottom: %x\n", bottom);
    uint16_t value = top + bottom;
    printf("Top Plus Bottom: %x\n", value);
    return ~value;
}


uint16_t ip_sum_calc(size_t len_ip_header, uint16_t buff[])
{
uint16_t word16;
uint32_t sum=0;
size_t i;
    
    // make 16 bit words out of every two adjacent 8 bit words in the packet
    // and add them up
    for (i=0;i<len_ip_header;i=i+1){
        word16 =((buff[i]<<8)&0xFF00)+(buff[i+1]&0xFF);
        sum = sum + (uint32_t) buff[i];       
    }
    
    // take only 16 bits out of the 32 bit sum and add up the carries
    while (sum>>16)
      sum = (sum & 0xFFFF)+(sum >> 16);

    // one's complement the result
    sum = ~sum;
    
return ((uint16_t) sum);
}

/* Compute Internet Checksum for "count" bytes
*         beginning at location "addr".
*/
long rfc_checksum(size_t count, uint8_t *addr) {
    register uint32_t sum = 0;

    while( count > 1 )  {
       /*  This is the inner loop */
           sum += * (uint16_t *) addr++;
           count -= 2;
    }

       /*  Add left-over byte, if any */
    if( count > 0 )
           sum += * (uint8_t *) addr;

    printf("Middle Sum: %x\n", sum);
    printf("Middle Sum: %d\n", sum);

       /*  Fold 32-bit sum to 16 bits */
    while (sum>>16)
       sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

