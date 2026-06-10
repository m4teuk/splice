#include "net/poller.h"

#include <poll.h>

namespace spl::net {

void Poller::set(int fd, std::function<void()> on_readable) {
    for (auto& e : fds_) {
        if (e.first == fd) {
            e.second = std::move(on_readable);
            return;
        }
    }
    fds_.emplace_back(fd, std::move(on_readable));
}

void Poller::remove(int fd) {
    for (auto it = fds_.begin(); it != fds_.end(); ++it) {
        if (it->first == fd) {
            fds_.erase(it);
            return;
        }
    }
}

void Poller::run(std::atomic<bool>& stop, const std::function<void(Millis)>& on_tick) {
    std::vector<pollfd> pfds;
    while (!stop.load()) {
        pfds.clear();
        for (const auto& e : fds_) pfds.push_back(pollfd{e.first, POLLIN, 0});
        ::poll(pfds.data(), static_cast<nfds_t>(pfds.size()), 100);

        for (const auto& p : pfds) {
            if (!(p.revents & (POLLIN | POLLHUP | POLLERR))) continue;
            // Look up fresh (a prior callback may have removed this fd) and copy
            // the function so a callback that removes itself stays alive while
            // it runs.
            for (const auto& e : fds_) {
                if (e.first == p.fd) {
                    auto cb = e.second;
                    cb();
                    break;
                }
            }
        }
        if (on_tick) on_tick(mono_ms());
    }
}

}  // namespace spl::net
