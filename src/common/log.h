// Dead-simple stderr logging. Not a hot path; good enough for a CLI/server.
#pragma once

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>

namespace spl {

inline void logf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// Human-readable byte count, e.g. "0 B", "41.2 KB", "1.3 MB".
inline std::string human_bytes(uint64_t n) {
    static const char* unit[] = {"B", "KB", "MB", "GB", "TB"};
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024.0 && i < 4) {
        v /= 1024.0;
        ++i;
    }
    char buf[40];
    if (i == 0)
        std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(n));
    else
        std::snprintf(buf, sizeof(buf), "%.1f %s", v, unit[i]);
    return buf;
}

}  // namespace spl
