#ifndef SR_UTIL_H
#define SR_UTIL_H

#include <time.h>
#include <inttypes.h>

__time_t sr_util_monotonic_secs();
uint16_t sr_util_ip_checksum(uint16_t *buf, int count);

#endif // SR_UTIL_H
