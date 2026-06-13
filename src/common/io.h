// Tiny blocking-write helper, shared by the daemon and its clients: write all n
// bytes (short writes resumed), giving up silently if the fd errors/closes.
#pragma once

#include <unistd.h>

#include <cstddef>

namespace spl {

inline void write_all(int fd, const void* p, size_t n) {
    const char* b = static_cast<const char*>(p);
    for (size_t off = 0; off < n;) {
        ssize_t w = ::write(fd, b + off, n - off);
        if (w <= 0) return;
        off += static_cast<size_t>(w);
    }
}

}  // namespace spl
