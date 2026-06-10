// Verbose renderer for PathStatus snapshots: diffs consecutive snapshots and
// logs path events (candidates appearing, going alive/dead, path switches) plus
// a periodic stats/candidate table. UI only — the path manager itself never
// logs. Used by the peer commands' -v flag.
#pragma once

#include "peer/pathman.h"

namespace spl::peer {

class PathWatch {
 public:
    void render(const PathStatus& cur, Millis now);

 private:
    PathStatus prev_;
    Millis t_stats_ = 0;
    bool first_ = true;
};

}  // namespace spl::peer
