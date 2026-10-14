#!/usr/bin/env python3
"""Kinds: an offer says what it is when you connect. `spl ls` shows each one with
the command that uses it, and connecting with the wrong command (getting from an
inbox, sending to a file share, opening a shell on something else) is refused
with that command, before any byte of the wrong protocol moves. `spl drop`
stops an offer."""
import os
import subprocess
import sys
import tempfile

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def main():
    port = free_port()
    srv = start_server(SPL, port)
    envs = []
    try:
        ld, fd = pair_two(SPL, port)
        A = ["--server", "127.0.0.1", "--port", str(port)]
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        envs = [lenv, fenv]

        def run(env, *args):
            return subprocess.run([SPL, *args, *A], env=env, capture_output=True, text=True,
                                  timeout=60)

        for env in (lenv, fenv):
            assert run(env, "start").returncode == 0

        work = tempfile.mkdtemp()
        report = os.path.join(work, "report.txt")
        open(report, "w").write("the report\n")
        inbox = os.path.join(work, "inbox")
        assert run(fenv, "serve", "theleader", report, "--name", "report").returncode == 0
        assert run(fenv, "inbox", "theleader", inbox).returncode == 0
        assert run(fenv, "revshell", "theleader").returncode == 0
        assert run(fenv, "pipe", "register", "theleader", "diag", "ECHO").returncode == 0

        # --- spl ls: what each offer is, and how to use it
        ls = run(lenv, "ls", "thefollower")
        assert ls.returncode == 0, ls.stderr
        rows = {l.split()[0]: l for l in ls.stdout.splitlines()[1:] if l.strip()}
        assert "sends files" in rows["report"] and "spl get thefollower report" in rows["report"], ls.stdout
        assert "receives files" in rows["inbox"] and "spl send thefollower <path>" in rows["inbox"], ls.stdout
        assert "a program on a terminal" in rows["shell"] and "spl shell thefollower" in rows["shell"], ls.stdout
        assert "a raw pipe" in rows["diag"] and "spl pipe open thefollower diag" in rows["diag"], ls.stdout
        print("  spl ls shows each offer's kind and the command for it")

        # --- the wrong command is refused, with the right one
        out = tempfile.mkdtemp()
        r = run(lenv, "get", "thefollower", "inbox", "-o", out)
        assert r.returncode != 0, r
        assert "receives files" in r.stderr and "spl send thefollower <path>" in r.stderr, r.stderr
        assert os.listdir(out) == [], "a refused get wrote something"

        r = run(lenv, "send", "thefollower", report, "--name", "report")
        assert r.returncode != 0, r
        assert "sends files" in r.stderr and "spl get thefollower report" in r.stderr, r.stderr

        r = run(lenv, "shell", "thefollower", "--name", "diag")
        assert r.returncode != 0 and "a raw pipe" in r.stderr, r.stderr

        r = run(lenv, "shell", "thefollower", "--name", "nope")
        assert r.returncode != 0 and "isn't offered" in r.stderr, r.stderr

        # …and the right one works
        assert run(lenv, "get", "thefollower", "report", "-o", out).returncode == 0
        assert open(os.path.join(out, "report.txt")).read() == "the report\n"
        r = run(lenv, "send", "thefollower", report)
        assert r.returncode == 0, r.stderr
        assert open(os.path.join(inbox, "report.txt")).read() == "the report\n"
        print("  the wrong command is refused and names the right one")

        # --- drop: by name alone (only one peer has it), or with the peer
        r = run(fenv, "drop", "report")
        assert r.returncode == 0 and "no longer offering 'report' to theleader" in r.stdout, r
        r = run(fenv, "drop", "theleader", "inbox")
        assert r.returncode == 0, r
        r = run(fenv, "drop", "report")
        assert r.returncode != 0 and "don't offer anything called 'report'" in r.stderr, r
        ls = run(lenv, "ls", "thefollower").stdout
        assert "report" not in ls and "inbox" not in ls and "shell" in ls, ls
        print("  spl drop stops an offer (peer optional when unambiguous)")

        # --- the plumbing lives under `spl pipe`
        r = run(fenv, "register", "theleader", "x", "ECHO")
        assert r.returncode == 2 and "spl pipe register" in r.stderr, r

        print("KINDS PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
