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
    "pairing", "files", "shells and chat", "what's going on", "the daemon", "plumbing", "other",
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
     "until you remove it with `spl unregister <peer> <name>`; the files are read\n"
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
     "needed). Like any offer it stays until `spl unregister <peer> <name>`.\n"
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
    {"chat", "shells and chat", "talk to a peer: a terminal on each end",
     "spl chat <peer>",
     "Both of you run `spl chat <the other>`; whoever is first waits. Lines you\n"
     "type appear on the other side. ^D (or ^C) ends it for both.\n"
     "\n"
     "options:\n"
     RELAY_OPT},

    {"revshell", "shells and chat", "let a peer open a shell on this machine",
     "spl revshell <peer> [--name NAME] [--limit N]",
     "Offers <peer> a shell on this machine, running as you: they can then run\n"
     "anything you can. They attach with `spl shell <you>`; each attach gets a\n"
     "fresh shell. The offer stays (across restarts too) until you remove it with\n"
     "`spl unregister <peer> <name>`. Shells already open keep running after that;\n"
     "end one with `spl close`.\n"
     "\n"
     "options:\n"
     "  --name NAME   offer it under another name (default: shell)\n"
     "  --limit N     remove the offer after N attaches (--limit 1: a one-off)\n"
     RELAY_OPT
     "\n"
     "see also: spl shell, spl status"},

    {"shell", "shells and chat", "open a shell a peer offers you",
     "spl shell <peer> [--name NAME]",
     "Opens a shell on <peer>, which it offered with `spl revshell`. Your terminal\n"
     "is handed over to it, like ssh; resizing it resizes the remote one.\n"
     "\n"
     "options:\n"
     "  --name NAME   which shell, if they offered it under another name\n"
     "                (default: shell)\n"
     RELAY_OPT
     "\n"
     "see also: spl revshell"},

    // ------------------------------------------------------------ what's going on
    {"status", "what's going on", "every peer: how it's connected, offers, transfers",
     "spl status [-v]",
     "For each peer: whether it's reached directly or through the relay and how\n"
     "fast, its settings, what you offer it, and every open connection with its\n"
     "progress. The numbers after `#` are what `spl close` takes.\n"
     "\n"
     "options:\n"
     "  -v, --verbose   also addresses, traffic per path, and every address tried"},

    {"ls", "what's going on", "what a peer offers you",
     "spl ls <peer>",
     "Asks <peer> what it offers you right now (the names you pass to `spl get`,\n"
     "`spl shell --name`, …). The peer has to be reachable.\n"
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
     "`spl unregister <peer> <name>`."},

    {"config", "the daemon", "show the config file and its values",
     "spl config",
     "Prints where the config file is and the values in effect: the relay, and\n"
     "the port this machine listens on for local discovery and pairing. Edit the\n"
     "file by hand to change them; restart the daemon (`spl stop`) to apply."},

    // ------------------------------------------------------------ plumbing
    {"register", "plumbing", "offer a raw pipe of any type",
     "spl register <peer> <name> [LIMIT N] <TYPE> [args...]",
     "The general form of serve/inbox/revshell: offer <name> to <peer>, with this\n"
     "machine's end of each connection made by <TYPE>.\n"
     "\n"
     "types:\n"
     "  ECHO               sends back what it receives (for testing)\n"
     "  SHARE_FILE <path>  sends a file or directory (what `serve` uses)\n"
     "  GET_FILE <dir> [OVERWRITE]   receives files (what `inbox` uses)\n"
     "  SHELL              a shell on this machine (what `revshell` uses)\n"
     "  PIPE               this terminal: stdin and stdout become the pipe, and\n"
     "                     the offer lasts as long as this command runs\n"
     "\n"
     "LIMIT N removes the offer after N connections.\n"
     "\n"
     "example:\n"
     "  spl register desk diagnostic ECHO\n"
     "\n"
     "see also: spl open, spl unregister"},

    {"unregister", "plumbing", "remove one offer",
     "spl unregister <peer> <name>",
     "Stops offering <name> to <peer>. Connections already made to it keep\n"
     "running (it tells you which); end them with `spl close`."},

    {"open", "plumbing", "connect to a peer's offer with a raw pipe",
     "spl open [--wait] <peer> <name> [<TYPE> [args...]]",
     "Connects to what <peer> offers as <name>, with this machine's end made by\n"
     "<TYPE> (see `spl help register`). Without a TYPE it's PIPE: stdin and stdout\n"
     "become the connection.\n"
     "\n"
     "options:\n"
     "  --wait   if <name> isn't offered yet, keep trying until it is\n"
     RELAY_OPT
     "\n"
     "example:\n"
     "  echo hello | spl open desk diagnostic\n"
     "\n"
     "see also: spl register, spl close"},

    {"close", "plumbing", "end one open connection",
     "spl close <peer> <id>",
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
    if (cmd == "peer") {
        if (is_help_flag(argv[2])) return std::string("peer");
        for (int i = 3; i < argc && std::string_view(argv[i]) != "--"; ++i)
            if (is_help_flag(argv[i])) {
                const std::string sub = "peer " + std::string(argv[2]);
                return find(sub) ? std::string(find(sub)->topic) : std::string("peer");
            }
        return std::nullopt;
    }
    if (!find(cmd)) return std::nullopt;  // unknown command: main reports it
    const bool typed = cmd == "register" || cmd == "open";
    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--" || (typed && is_type_word(a))) break;
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
