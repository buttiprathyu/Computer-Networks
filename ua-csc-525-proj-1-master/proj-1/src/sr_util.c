#include <stdio.h>
#include <netinet/in.h>

#include "sr_util.h"

__time_t sr_util_monotonic_secs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

uint16_t sr_util_ip_checksum(uint16_t *buf, int count)
{
    uint32_t sum = 0;
    while (count--)
    {
        sum += ntohs(*buf++);
        if (sum & 0xFFFF0000)
        {
            /* carry occurred,
            so wrap around */
            sum &= 0xFFFF;
            sum++;
        }
    }
    return (uint16_t)(~(sum & 0xFFFF));
}
