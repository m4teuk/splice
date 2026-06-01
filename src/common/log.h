// Dead-simple stderr logging. Not a hot path; good enough for a CLI/server.
#pragma once

#include <cstdarg>
#include <cstdio>

namespace spl {

inline void logf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

}  // namespace spl
