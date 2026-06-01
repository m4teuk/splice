// Hidden `spl __datatest <name>` command: drives the path manager with
// hand-crafted inner IPv6 echo packets (no lwIP yet) to validate the transport
// — relay first, then upgrade to a direct path.
#pragma once

namespace spl::peer {

int datatest_main(int argc, char** argv);  // argv[0] == "__datatest"

}  // namespace spl::peer
