#include "peer/pipes.h"

namespace spl::peer {

std::unique_ptr<LocalEnd> make_local_end(const std::string& type,
                                         const std::vector<std::string>& args, std::string* err) {
    if (type == "ECHO") {
        if (!args.empty()) {
            if (err) *err = "ECHO takes no arguments";
            return nullptr;
        }
        return std::make_unique<EchoEnd>();
    }
    if (err) *err = "unknown pipe type '" + type + "'";
    return nullptr;
}

}  // namespace spl::peer
