#!/usr/bin/env python3
"""Help: every command (and every `spl peer` subcommand) has a page, reachable as
`spl help X` and `spl X --help`; asking for help never runs the command; a
misused command prints its usage and exits 2."""
import os
import subprocess
import sys
import tempfile

SPL = sys.argv[1]


def main():
    env = dict(os.environ, SPL_CONFIG_DIR=tempfile.mkdtemp(), SPL_RUNTIME_DIR=tempfile.mkdtemp())

    def run(*args):
        return subprocess.run([SPL, *args], env=env, capture_output=True, text=True, timeout=15)

    overview = run("--help")
    assert overview.returncode == 0 and "usage: spl <command>" in overview.stdout, overview

    # the command list completion offers is the real one: each has a page, and
    # the overview lists it
    cmds = run("__complete", "1", "spl").stdout.split()
    subs = run("__complete", "2", "spl", "peer").stdout.split()
    assert len(cmds) > 20 and len(subs) >= 7, (cmds, subs)
    for c in cmds:
        assert f"\n  {c} " in overview.stdout, f"`{c}` missing from the overview"
    topics = [[c] for c in cmds] + [["peer", s] for s in subs]
    for t in topics:
        page = run("help", *t)
        assert page.returncode == 0 and "usage: spl " + " ".join(t) in page.stdout, (t, page)
        for flag in ("--help", "-h"):
            r = run(*t, flag)
            assert r.returncode == 0 and r.stdout == page.stdout, (t, flag, r)
    print(f"  {len(topics)} pages, each the same via `spl help X` and `spl X --help`")

    # help is asked for, so nothing runs: no daemon is started, nothing is wiped
    for t in (["start"], ["reset"], ["update"], ["pair"], ["stop"], ["peer", "remove", "x"],
              ["get", "x", "y"], ["register", "x", "y"]):
        r = run(*t, "--help")
        assert r.returncode == 0 and "usage:" in r.stdout, (t, r)
    assert not os.listdir(env["SPL_RUNTIME_DIR"]), "a --help started the daemon"
    print("  --help never runs the command")

    # …but past a pipe TYPE, --help belongs to the pipe's arguments
    r = run("register", "nobody", "x", "SHARE_FILE", "--help", "--server", "127.0.0.1", "--port", "1")
    assert "usage: spl register" not in r.stdout, r
    run("stop")  # that one did reach the daemon

    # misuse: the reason, the usage, where to read more — on stderr, exit 2
    for args, why in ((["get", "alice"], ""), (["get", "a", "b", "--bogus"], "unknown option"),
                      (["reset", "desk"], "unexpected 'desk'"), (["peer", "frob"], "unknown command"),
                      (["pair", "a", "b"], "too many"), (["update", "now"], "")):
        r = run(*args)
        assert r.returncode == 2 and why in r.stderr and "usage: spl" in r.stderr, (args, r)
        assert "more: spl help" in r.stderr, (args, r)
    assert run("help", "nope").returncode == 2 and run("nope").returncode == 2
    print("  misuse prints the usage and exits 2")

    print("HELP PASSED")


if __name__ == "__main__":
    main()
