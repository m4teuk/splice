#include "peer/peer_cmd.h"

#include <cstdio>
#include <ctime>
#include <string>

#include "common/base64.h"
#include "common/log.h"
#include "peer/pairing.h"
#include "peer/store.h"

namespace spl::peer {

namespace {

void usage() {
    spl::logf(
        "usage:\n"
        "  spl peer list | ls            list paired connections\n"
        "  spl peer rename <old> <new>   rename a connection\n"
        "  spl peer remove <name>        delete a connection\n"
        "  spl peer add [pair options]   pair with a new peer (alias for `spl pair`)");
}

int do_list() {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    auto names = store->list();
    if (names.empty()) {
        std::printf("No paired connections.\n");
        return 0;
    }
    for (const auto& n : names) {
        auto r = store->load(n);
        if (!r) continue;
        char date[32] = "?";
        time_t t = static_cast<time_t>(r->created_unix);
        struct tm tm;
        if (localtime_r(&t, &tm)) std::strftime(date, sizeof(date), "%Y-%m-%d", &tm);
        std::printf("%-20s  %-8s  %s  (paired %s)\n", n.c_str(), r->side ? "follower" : "leader",
                    base64_encode(as_span(r->peer_pub)).c_str(), date);
    }
    return 0;
}

int do_rename(const std::string& from, const std::string& to) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    if (!store->rename(from, to, &err)) {
        spl::logf("rename failed: %s", err.c_str());
        return 1;
    }
    std::printf("renamed '%s' -> '%s'\n", from.c_str(), to.c_str());
    return 0;
}

int do_remove(const std::string& name) {
    std::string err;
    auto store = Store::open(&err);
    if (!store) {
        spl::logf("%s", err.c_str());
        return 1;
    }
    if (!store->remove(name)) {
        spl::logf("no connection named '%s'", name.c_str());
        return 1;
    }
    std::printf("removed '%s'\n", name.c_str());
    return 0;
}

}  // namespace

int peer_cmd_main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    std::string sub = argv[1];
    if (sub == "list" || sub == "ls") return do_list();
    if (sub == "rename") {
        if (argc < 4) {
            usage();
            return 2;
        }
        return do_rename(argv[2], argv[3]);
    }
    if (sub == "remove" || sub == "rm") {
        if (argc < 3) {
            usage();
            return 2;
        }
        return do_remove(argv[2]);
    }
    if (sub == "add") return pair_main(argc - 1, argv + 1);  // argv+1[0] == "add"
    usage();
    return 2;
}

}  // namespace spl::peer
