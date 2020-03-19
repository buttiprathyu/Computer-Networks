#include <stdio.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <string.h>

#include "sr_util.h"
#include "sr_debug.h"

__time_t sr_util_monotonic_secs()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec;
}

// Implementation courtesy of
// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
uint16_t sr_util_ip_checksum(void *vdata, size_t length)
{
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

bool sr_util_is_in_window(uint64_t window_start, uint64_t window_size, uint64_t val, size_t datatype_bytes)
{
    uint64_t mod = 1 << (datatype_bytes * 8);
    window_start %= mod;
    window_size %= mod;
    val %= mod;
    uint64_t window_end = (window_start + window_size) % mod;
    if(window_end < window_start)
    {
        // off the end of the window
        if(val > window_start || val <= window_end) return true;
    }
    else if(val > window_start && val <= window_end) return true;
    return false;
}
