#pragma once

namespace spl::peer {
// `spl __complete <cword> <word0=spl> <word1> …`: prints newline-separated
// completion candidates for the word at index <cword>, or the sentinel
// __FILES__ / __DIRS__ to tell the shell to complete paths. Pure-local and
// fast; never starts the daemon. Driven by the shell wrappers in completions/.
int complete_main(int argc, char** argv);
}  // namespace spl::peer
