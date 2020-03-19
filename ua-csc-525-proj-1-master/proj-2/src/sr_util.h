#ifndef SR_UTIL_H
#define SR_UTIL_H

#include <time.h>
#include <inttypes.h>
#include <stdbool.h>

__time_t sr_util_monotonic_secs();

// result is in network order
uint16_t sr_util_ip_checksum(void *vdata, size_t length);

// checks if you're within a moving window
// also accounts for wraparound as long as window_start + window_size
// is less than uint64_t's maximum possible value.
bool sr_util_is_in_window(uint64_t window_start, uint64_t window_size, uint64_t val, size_t datatype_size);

#endif // SR_UTIL_H
