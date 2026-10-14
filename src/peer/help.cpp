#include "peer/help.h"

#include <cstdio>
#include <string>
#include <string_view>

namespace spl::peer {

namespace {

// One help page. `usage` is what a misused command prints; `body` is the rest of
// the page (what it does, options, examples, see also); `summary` is its line in
// the overview, under `group` (empty = a page that isn't listed there).
struct Page {
    const char* topic;
    const char* group;
    const char* summary;
    const char* usage;
    const char* body;
};

#define RELAY_OPT "  --server HOST --port N   the relay to use (default: see `spl config`)\n"

// The overview lists the groups in this order.
constexpr const char* kGroups[] = {
    "pairing", "files", "programs and chat", "what's going on", "the daemon", "other",
};

constexpr Page kPages[] = {
    // ------------------------------------------------------------ pairing
    {"pair", "pairing", "pair this machine with another one (once per pair)",
     "spl pair [--name NAME] [--local]\n"
     "spl pair <code> [--name NAME] [--at HOST[:PORT]] [--lan-port N]",
     "Run `spl pair` on one machine: it prints a code. Run `spl pair <code>` on\n"
     "the other. The code is used once, to agree on keys: a mistyped or guessed\n"
     "code fails rather than pairing you with someone else. Both sides then show\n"
     "both keys (compare them if you like) and ask for a name for the other one.\n"
     "\n"
     "Pairing goes through the relay when it's reachable. Without it (offline, or\n"
     "with --local) it happens over the local network instead: the code starts\n"
     "with L (L37-481922) and the joining machine finds this one by broadcast.\n"
     "\n"
     "options:\n"
     "  --name NAME        accept, and store the peer as NAME, without asking\n"
     "  --local            pair over the local network even if the relay is up\n"
     "  --at HOST[:PORT]   (joining a local code) where the other machine is when\n"
     "                     it isn't on this network: a VPN or Tailscale address\n"
     "  --lan-port N       (joining a local code) the other machine's LAN port, if\n"
     "                     it changed it (its `spl pair` tells you when)\n"
     "  --insecure         carry on when the relay's TLS certificate can't be\n"
     "                     verified (the pairing itself is still checked end to end)\n"
     "  -v, --verbose\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl pair                        on the first machine\n"
     "  spl pair 3-481922 --name desk   on the second\n"
     "\n"
     "see also: spl peer"},

    {"peer", "pairing", "your paired peers: list, inspect, rename, remove, settings",
     "spl peer <command> [args]",
     "commands:\n"
     "  ls                                  every paired peer, one line each\n"
     "  show <peer>                         everything about one peer\n"
     "  rename <peer> <new-name>            call a peer something else\n"
     "  remove <peer>                       forget a peer (unpair)\n"
     "  add-address <peer> <host[:port]>    also look for the peer at an address\n"
     "  remove-address <peer> <host[:port]> stop looking there\n"
     "  set <peer> <setting> <value>        change how spl reaches the peer\n"
     "\n"
     "Changes apply to a running daemon right away.\n"
     "`spl help peer <command>` describes each one.\n"
     "\n"
     "see also: spl pair, spl ls (what a peer offers you)"},

    {"peer ls", "", "list your paired peers", "spl peer ls",
     "Lists your paired peers: the name, when you paired, its settings (see\n"
     "`spl help peer set`), and how many addresses spl knows for it.\n"
     "\n"
     "see also: spl peer show, spl status"},

    {"peer show", "", "everything about one peer", "spl peer show <peer>",
     "Everything stored about one peer: both keys, when you paired, its settings,\n"
     "its LAN port, the addresses you added and the ones spl remembered because\n"
     "they worked."},

    {"peer rename", "", "call a peer something else", "spl peer rename <peer> <new-name>",
     "Renames a peer. What you offer it, and connections that are open, carry\n"
     "over to the new name. Only your side changes: the peer calls you whatever\n"
     "it called you before."},

    {"peer remove", "", "forget a peer (unpair)", "spl peer remove <peer>",
     "Forgets a peer: its keys, settings, addresses and everything you offered\n"
     "it. Its connections are closed at once and it can't reach you any more.\n"
     "Getting it back means pairing again.\n"
     "\n"
     "alias: spl peer rm"},

    {"peer add-address", "", "also look for a peer at an address", "spl peer add-address <peer> <host[:port]>",
     "Tells spl to also look for the peer at an address: a LAN IP, a Tailscale\n"
     "or VPN name, a hostname. It's a hint, not a promise: spl tries it along with\n"
     "the relay and the local network and uses whichever path answers. Leave out\n"
     "the port to use the peer's LAN port.\n"
     "\n"
     "examples:\n"
     "  spl peer add-address desk 192.168.1.20\n"
     "  spl peer add-address desk desk.tailnet-name.ts.net\n"
     "\n"
     "see also: spl peer remove-address, spl peer show"},

    {"peer remove-address", "", "stop looking for a peer at an address", "spl peer remove-address <peer> <host[:port]>",
     "Stops looking for the peer at an address you added. It also forgets an\n"
     "address spl remembered on its own (see `spl peer show`)."},

    {"peer set", "", "change how spl reaches a peer", "spl peer set <peer> <setting> <on|off>\n"
                         "spl peer set <peer> lan-port <N|default>",
     "Changes how spl reaches one peer. Everything is on by default.\n"
     "\n"
     "settings:\n"
     "  relay              use the relay server to reach this peer. Off means only\n"
     "                     the local network and the addresses you added.\n"
     "  lan-discovery      look for this peer on local networks by broadcast\n"
     "  remember-address   save the last addresses that worked and try them first\n"
     "  lan-port           the port the peer listens on for local discovery. The\n"
     "                     peer tells you this itself, so set it only to fix a\n"
     "                     peer that can't (an older version); `default` undoes it.\n"
     "\n"
     "example:\n"
     "  spl peer set desk relay off"},

    // ------------------------------------------------------------ files
    {"serve", "files", "offer a file or directory for a peer to fetch",
     "spl serve <peer> <path> [--name NAME] [--limit N]",
     "Offers <path> to <peer>, who fetches it with `spl get`. A directory is sent\n"
     "whole, with everything under it. The offer stays (across restarts too)\n"
     "until you stop it with `spl drop <peer> <name>`; the files are read\n"
     "when the peer fetches them, not now.\n"
     "\n"
     "options:\n"
     "  --name NAME   the name the peer asks for (default: the file's name)\n"
     "  --limit N     remove the offer after N fetches\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl serve desk report.pdf                 desk runs: spl get laptop report.pdf\n"
     "  spl serve desk ~/photos --name pics --limit 1\n"
     "\n"
     "see also: spl get, spl send (push instead), spl status"},

    {"get", "files", "fetch a file or directory a peer offers you",
     "spl get <peer> <name> [-o PATH] [-f] [-b]",
     "Fetches what <peer> offers as <name> (see `spl ls <peer>`). An interrupted\n"
     "fetch continues where it stopped when you run the same command again, and\n"
     "each file is checked before it's put in place.\n"
     "\n"
     "options:\n"
     "  -o, --out PATH     where to save. An existing directory gets the files\n"
     "                     inside it; anything else is the file name to write.\n"
     "                     (default: the current directory)\n"
     "  -f, --force        replace files that already exist (otherwise that's an\n"
     "                     error)\n"
     "  -b, --background   start it and return; follow it in `spl status`\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl get laptop report.pdf\n"
     "  spl get laptop pics -o ~/Pictures\n"
     "\n"
     "see also: spl serve, spl ls"},

    {"inbox", "files", "let a peer push files into a directory",
     "spl inbox <peer> <dir> [--name NAME] [--limit N] [-f]",
     "Lets <peer> send you files with `spl send`; they land in <dir> (created if\n"
     "needed). Like any offer it stays until `spl drop <peer> <name>`.\n"
     "\n"
     "options:\n"
     "  --name NAME   offer it under another name, to have several inboxes for one\n"
     "                peer; the sender then picks it with `--name` (default: inbox)\n"
     "  --limit N     close the inbox after N pushes\n"
     "  -f, --force   let pushes replace files that already exist in <dir>\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl inbox laptop ~/Downloads\n"
     "  spl inbox laptop ~/Videos --name media\n"
     "\n"
     "see also: spl send"},

    {"send", "files", "push files into a peer's inbox",
     "spl send <peer> <path>... [--name NAME] [-b]",
     "Sends each <path> (a file or a whole directory) into the inbox <peer>\n"
     "opened for you with `spl inbox`. Works only if they did.\n"
     "\n"
     "options:\n"
     "  --name NAME        which of the peer's inboxes (default: inbox)\n"
     "  -b, --background   start it and return; follow it in `spl status`\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl send desk report.pdf notes/\n"
     "  spl send desk movie.mkv --name media\n"
     "\n"
     "see also: spl inbox, spl serve (offer instead of push)"},

    // ------------------------------------------------------------ shells and chat
    {"chat", "programs and chat", "talk to a peer: a terminal on each end",
     "spl chat <peer>",
     "Both of you run `spl chat <the other>`; whoever is first waits. Lines you\n"
     "type appear on the other side. ^D (or ^C) ends it for both.\n"
     "\n"
     "options:\n"
     RELAY_OPT},

    {"revshell", "programs and chat", "let a peer open a shell on this machine",
     "spl revshell <peer> [--name NAME] [--limit N]",
     "Offers <peer> your login shell on this machine, running as you: they can\n"
     "then run anything you can. They attach with `spl shell <you>`; each attach\n"
     "gets a fresh shell (the same as `spl expose --pty --name shell $SHELL`). The offer stays (across restarts too) until you remove it with\n"
     "`spl drop <peer> <name>`. Shells already open keep running after that;\n"
     "end one with `spl pipe close`.\n"
     "\n"
     "options:\n"
     "  --name NAME   offer it under another name (default: shell)\n"
     "  --limit N     remove the offer after N attaches (--limit 1: a one-off)\n"
     RELAY_OPT
     "\n"
     "see also: spl shell, spl status"},

    {"shell", "programs and chat", "open a shell (or terminal program) a peer offers you",
     "spl shell <peer> [--name NAME]",
     "Opens a shell on <peer>, which it offered with `spl revshell` (or another\n"
     "program it offered on a terminal: `spl expose --pty`). Your terminal is\n"
     "handed over to it, like ssh; resizing it resizes the remote one.\n"
     "\n"
     "Exits with the shell's status (`exit 3` there gives 3 here); 255 means spl\n"
     "itself failed: the peer unreachable, nothing offered under that name, or\n"
     "the connection lost.\n"
     "\n"
     "options:\n"
     "  --name NAME   which one, if they offered it under another name\n"
     "                (default: shell)\n"
     RELAY_OPT
     "\n"
     "see also: spl revshell, spl run"},

    {"run", "programs and chat", "run a program a peer offers you",
     "spl run <peer> <name>",
     "Runs the program <peer> offers as <name> (with `spl expose`), with your\n"
     "stdin, stdout and stderr connected to it. Its command line is fixed by\n"
     "whoever offers it: you only give it input. ^C stops it.\n"
     "\n"
     "Exits with the program's status: its exit code, or 128 + the signal that\n"
     "killed it. 255 means spl itself failed: the peer unreachable, <name> not\n"
     "offered or not a program, or the connection lost mid-run (the program is\n"
     "then stopped on the peer).\n"
     "\n"
     "options:\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl run desk backup && echo backed up\n"
     "  tar c photos | spl run nas store-photos\n"
     "\n"
     "see also: spl expose, spl ls (what a peer offers you)"},

    {"expose", "programs and chat", "let a peer run a program on this machine",
     "spl expose <peer> [--name NAME] [--pty] [--limit N] <program> [args...]",
     "Lets <peer> run <program>, with exactly these arguments, using `spl run`.\n"
     "Each run is a fresh process: running as you, in your home directory, with\n"
     "SPL_PEER set to the peer's name. The peer only gives it input; it can't\n"
     "change the command line. When the connection drops, the program is hung up\n"
     "(SIGHUP, then SIGKILL 5 seconds later).\n"
     "\n"
     "Options go before <program>: from <program> on, everything is its command\n"
     "line. Choose with care: a program that takes commands from its input (sh,\n"
     "python, ssh, ...) gives the peer a shell all the same. The offer stays\n"
     "(across restarts too) until `spl drop <peer> <name>`.\n"
     "\n"
     "options:\n"
     "  --name NAME   the name the peer runs it by (default: the program's file name)\n"
     "  --pty         run it on a terminal (for interactive programs); the peer\n"
     "                then uses `spl shell <you> --name NAME`\n"
     "  --limit N     remove the offer after N runs\n"
     RELAY_OPT
     "\n"
     "examples:\n"
     "  spl expose desk ~/bin/backup --full\n"
     "  spl expose desk --name logs journalctl -n 200\n"
     "  spl expose desk --pty htop\n"
     "\n"
     "see also: spl run, spl revshell, spl drop"},

    // ------------------------------------------------------------ what's going on
    {"status", "what's going on", "every peer: how it's connected, offers, transfers",
     "spl status [-v]",
     "For each peer: whether it's reached directly or through the relay and how\n"
     "fast, its settings, what you offer it, and every open connection with its\n"
     "progress. The numbers after `#` are what `spl pipe close` takes.\n"
     "\n"
     "options:\n"
     "  -v, --verbose   also addresses, traffic per path, and every address tried"},

    {"ls", "what's going on", "what a peer offers you",
     "spl ls <peer>",
     "Asks <peer> what it offers you right now: each name, what it is (sends\n"
     "files, receives files, a shell, …) and the command that uses it. The peer\n"
     "has to be reachable.\n"
     "\n"
     "options:\n"
     RELAY_OPT
     "\n"
     "see also: spl peer ls (your paired peers)"},

    {"ping", "what's going on", "is a peer reachable right now?",
     "spl ping <peer>",
     "Checks that <peer> answers, and how long a round trip takes. Exits 1 if it\n"
     "doesn't answer within 5 seconds.\n"
     "\n"
     "options:\n"
     RELAY_OPT},

    {"drop", "what's going on", "stop offering something to a peer",
     "spl drop [<peer>] <name>",
     "Stops offering <name>: a file you serve, an inbox, a shell. Leave out <peer>\n"
     "when only one peer is offered that name. Connections already open carry on\n"
     "(it tells you which); end them with `spl pipe close`.\n"
     "\n"
     "examples:\n"
     "  spl drop report.pdf\n"
     "  spl drop desk inbox\n"
     "\n"
     "see also: spl status (what you offer), spl reset (stop offering everything)"},

    // ------------------------------------------------------------ the daemon
    {"start", "the daemon", "run the daemon and keep it running",
     "spl start [--foreground]",
     "spl runs a background daemon per user that holds your connections. Any\n"
     "command starts it when needed, and then it stops by itself after a couple\n"
     "of idle minutes. `spl start` starts it (or keeps a running one) for good,\n"
     "until `spl stop`.\n"
     "\n"
     "options:\n"
     "  --foreground   run in this terminal instead of the background (logs here)\n"
     RELAY_OPT},

    {"stop", "the daemon", "stop the daemon",
     "spl stop",
     "Stops the daemon. Open connections and transfers end; offers you made are\n"
     "kept and come back with the next start."},

    {"reload", "the daemon", "make the daemon re-read the peer files",
     "spl reload",
     "Only needed after editing the files under the config directory by hand:\n"
     "`spl pair` and `spl peer` already tell the daemon. A removed peer is\n"
     "dropped at once; a renamed one keeps its connections."},

    {"reset", "the daemon", "remove every offer, for every peer",
     "spl reset",
     "Removes everything you offer, to every peer, and closes the connections\n"
     "made to those offers. Your pairings are kept. To remove one offer use\n"
     "`spl drop`."},

    {"config", "the daemon", "show the config file and its values",
     "spl config",
     "Prints where the config file is and the values in effect: the relay, and\n"
     "the port this machine listens on for local discovery and pairing. Edit the\n"
     "file by hand to change them; restart the daemon (`spl stop`) to apply."},

    // ------------------------------------------------------------ plumbing
    {"pipe", "other", "raw pipes: what every other command is built on",
     "spl pipe <command> [args]",
     "commands:\n"
     "  register <peer> <name> [LIMIT N] <TYPE> [args...]   offer a pipe\n"
     "  unregister <peer> <name>                         stop offering it\n"
     "  open [--wait] <peer> <name> [<TYPE> [args...]]   connect to an offer\n"
     "  close <peer> <id>                                end one connection\n"
     "\n"
     "`spl help pipe <command>` describes each one, and docs/PIPES.md the model."},

    {"pipe register", "", "offer a raw pipe of any type",
     "spl pipe register <peer> <name> [LIMIT N] <TYPE> [args...]",
     "The general form of serve/inbox/revshell: offer <name> to <peer>, with this\n"
     "machine's end of each connection made by <TYPE>.\n"
     "\n"
     "types:\n"
     "  ECHO               sends back what it receives (for testing)\n"
     "  SHARE_FILE <path>  sends a file or directory (what `serve` uses)\n"
     "  GET_FILE <dir> [OVERWRITE]   receives files (what `inbox` uses)\n"
     "  EXEC [PTY] <program> [args...]   runs a program per connection (what\n"
     "                     `expose` uses); PTY puts it on a terminal\n"
     "  SHELL              the login shell on a terminal (what `revshell` uses)\n"
     "  PIPE               this terminal: stdin and stdout become the pipe, and\n"
     "                     the offer lasts as long as this command runs\n"
     "\n"
     "LIMIT N removes the offer after N connections.\n"
     "\n"
     "example:\n"
     "  spl pipe register desk diagnostic ECHO\n"
     "\n"
     "see also: spl pipe open, spl drop"},

    {"pipe unregister", "", "stop offering a pipe",
     "spl pipe unregister <peer> <name>",
     "Stops offering <name> to <peer> (the same as `spl drop <peer> <name>`).\n"
     "Connections already made to it keep running (it tells you which); end them\n"
     "with `spl pipe close`."},

    {"pipe open", "", "connect to a peer's offer with a raw pipe",
     "spl pipe open [--wait] <peer> <name> [<TYPE> [args...]]",
     "Connects to what <peer> offers as <name>, with this machine's end made by\n"
     "<TYPE> (see `spl help pipe register`). Without a TYPE it's PIPE: stdin and\n"
     "stdout become the connection. A TYPE that needs a particular kind of offer\n"
     "(GET_FILE needs one that sends files) refuses anything else.\n"
     "\n"
     "options:\n"
     "  --wait   if <name> isn't offered yet, keep trying until it is\n"
     RELAY_OPT
     "\n"
     "example:\n"
     "  echo hello | spl pipe open desk diagnostic\n"
     "\n"
     "see also: spl pipe register, spl pipe close"},

    {"pipe close", "", "end one open connection",
     "spl pipe close <peer> <id>",
     "Ends the connection with this id (the `#` number in `spl status`), whether\n"
     "you opened it or the peer connected to your offer. The offer stays."},

    // ------------------------------------------------------------ other
    {"server", "other", "run your own relay and pairing server",
     "spl server [options]",
     "Runs the server that helps peers pair and relays their traffic when they\n"
     "can't reach each other directly. It never sees what they send: everything\n"
     "is encrypted end to end. The first run without a config walks you through\n"
     "setting it up.\n"
     "\n"
     "options:\n"
     "  --setup          run the setup walkthrough again\n"
     "  --bind HOST      address to listen on\n"
     "  --port N         the port for both pairing (TCP) and relaying (UDP)\n"
     "  --tcp-port N     a different port for pairing\n"
     "  --udp-port N     a different port for relaying\n"
     "  --cert FILE      TLS certificate (PEM); a temporary self-signed one if\n"
     "                   left out\n"
     "  --key FILE       TLS private key (PEM)\n"
     "  -v, --verbose"},

    {"update", "other", "install the latest spl over this one",
     "spl update",
     "Runs the installer again (the `curl ... | bash` from the README), which\n"
     "fetches the latest release and replaces this binary."},

    {"help", "other", "this overview, or the details of one command",
     "spl help [<command> [<subcommand>]]",
     "`spl <command> --help` shows the same page."},
};

#undef RELAY_OPT

const Page* find(std::string_view topic) {
    if (topic == "peer list") topic = "peer ls";
    if (topic == "peer rm") topic = "peer remove";
    for (const auto& p : kPages)
        if (topic == p.topic) return &p;
    return nullptr;
}

void print_usage_lines(FILE* f, const char* usage) {
    std::string_view u = usage;
    bool first = true;
    while (!u.empty()) {
        const size_t nl = u.find('\n');
        const std::string_view line = u.substr(0, nl);
        std::fprintf(f, "%s%.*s\n", first ? "usage: " : "       ", static_cast<int>(line.size()),
                     line.data());
        first = false;
        u = nl == std::string_view::npos ? std::string_view{} : u.substr(nl + 1);
    }
}

bool is_help_flag(std::string_view a) { return a == "-h" || a == "--help"; }

// A pipe TYPE word (ECHO, SHARE_FILE, …): what follows it belongs to the pipe.
bool is_type_word(std::string_view a) {
    if (a.size() < 2) return false;
    for (char c : a)
        if (!((c >= 'A' && c <= 'Z') || c == '_')) return false;
    return a != "LIMIT";
}

}  // namespace

void print_overview(bool to_stderr) {
    FILE* f = to_stderr ? stderr : stdout;
    std::fprintf(f,
                 "spl: byte pipes between your machines, end to end encrypted\n"
                 "\n"
                 "usage: spl <command> [args]\n");
    for (const char* g : kGroups) {
        std::fprintf(f, "\n%s\n", g);
        for (const auto& p : kPages)
            if (std::string_view(p.group) == g)
                std::fprintf(f, "  %-12s %s\n", p.topic, p.summary);
    }
    std::fprintf(f,
                 "\n"
                 "`spl help <command>` or `spl <command> --help` for the details of one.\n"
                 "`spl --version` prints the version.\n");
}

bool print_help(const std::string& topic) {
    const Page* p = find(topic);
    if (!p) return false;
    if (*p->summary) std::printf("spl %s: %s\n\n", p->topic, p->summary);
    print_usage_lines(stdout, p->usage);
    std::printf("\n%s\n", p->body);
    return true;
}

std::optional<std::string> help_request(int argc, char** argv) {
    if (argc < 3) return std::nullopt;
    const std::string cmd = argv[1];
    if (cmd == "peer" || cmd == "pipe") {  // a group: its page, or a subcommand's
        if (is_help_flag(argv[2])) return cmd;
        const std::string sub = cmd + " " + argv[2];
        const bool typed = sub == "pipe register" || sub == "pipe open";
        for (int i = 3; i < argc; ++i) {
            const std::string_view a = argv[i];
            if (a == "--" || (typed && is_type_word(a))) break;
            if (is_help_flag(a)) return find(sub) ? std::string(find(sub)->topic) : cmd;
        }
        return std::nullopt;
    }
    if (!find(cmd)) return std::nullopt;  // unknown command: main reports it
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--") break;
        if (is_help_flag(a)) return cmd;
    }
    return std::nullopt;
}

int usage_error(const std::string& topic, const std::string& why) {
    const Page* p = find(topic);
    if (!why.empty()) std::fprintf(stderr, "spl %s: %s\n", topic.c_str(), why.c_str());
    if (!p) return 2;
    print_usage_lines(stderr, p->usage);
    std::fprintf(stderr, "more: spl help %s\n", p->topic);
    return 2;
}

}  // namespace spl::peer
