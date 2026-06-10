// A minimal poll(2) event loop: readable-fd callbacks plus a per-round tick.
// Owned by whoever runs the process's loop (today the peer commands via
// PeerRuntime; the daemon later). Callbacks may add/remove fds, including
// removing themselves.
#pragma once

#include <atomic>
#include <functional>
#include <utility>
#include <vector>

#include "common/time.h"

namespace spl::net {

class Poller {
 public:
    void set(int fd, std::function<void()> on_readable);  // add or replace
    void remove(int fd);

    // Poll until `stop` becomes true. Each round waits at most 100ms, invokes
    // the callbacks of readable fds, then on_tick(now).
    void run(std::atomic<bool>& stop, const std::function<void(Millis)>& on_tick);

 private:
    std::vector<std::pair<int, std::function<void()>>> fds_;
};

}  // namespace spl::net
