// lwIP architecture port for gcc/clang on Linux.
#ifndef SPL_ARCH_CC_H
#define SPL_ARCH_CC_H

#include <endian.h>  // provides BYTE_ORDER / LITTLE_ENDIAN / BIG_ENDIAN on glibc
#include <stdio.h>
#include <stdlib.h>

#define LWIP_PLATFORM_ASSERT(x)                                                       \
    do {                                                                              \
        fprintf(stderr, "lwip assert: \"%s\" at %s:%d\n", (x), __FILE__, __LINE__);  \
        fflush(stderr);                                                               \
        abort();                                                                      \
    } while (0)

#define LWIP_PLATFORM_DIAG(x) \
    do {                      \
        printf x;             \
    } while (0)

#endif  // SPL_ARCH_CC_H
