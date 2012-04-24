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

    uint16_t checksum = checksum(10, buf2);
    printf("Checksum: %x\n", checksum);
    printf("Expected: %x\n", 0xa5fa);
    return 0;
}
*/

uint16_t checksum(size_t bytepairs, uint8_t buf[])
{
    uint32_t sum = 0;
    for(int i = 0; i < bytepairs; i += 2) {
        sum += * ((uint16_t*) (buf + i));
//        sum += buf[i];
    }

    if(bytepairs % 2 == 1) {
        sum += buf[bytepairs - 1];
    }

    uint16_t top = sum >> 16;
    uint16_t bottom = sum & 0xffff;
    uint16_t value = top + bottom;
    return ~value;
}
