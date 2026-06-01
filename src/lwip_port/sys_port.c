// NO_SYS port: lwIP only needs a monotonic millisecond clock.
#include <time.h>

#include "lwip/sys.h"

u32_t sys_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)((u64_t)ts.tv_sec * 1000 + (u64_t)ts.tv_nsec / 1000000);
}
