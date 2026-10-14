#!/usr/bin/env python3
"""EXEC: `spl expose` offers a program, `spl run` runs it. Input, output and
errors are kept apart, input can end while output continues, the program's
status becomes ours (255 is spl's own failure), large input and output are
flow-controlled end to end, and a run whose connection goes away is stopped."""
import os
import signal
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    # a zombie still "exists": count it as gone
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().split(")")[-1].split()[0] != "Z"
    except FileNotFoundError:
        return True  # no /proc (macOS): trust kill(0)


def wait_for(cond, secs):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.1)
    return cond()


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
        work = tempfile.mkdtemp()

        def spl(env, *args, **kw):
            kw.setdefault("capture_output", True)
            kw.setdefault("timeout", 60)
            return subprocess.run([SPL, *args, *A], env=env, **kw)

        def expose(*args):  # spl's own options go before the program's command line
            r = subprocess.run([SPL, "expose", *A, "theleader", *args], env=fenv,
                               capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stdout + r.stderr
            return r.stdout

        for env in (lenv, fenv):
            assert spl(env, "start").returncode == 0

        out = expose("--name", "t", "sh", "-c", "cat; echo oops >&2; exit 3")
        assert "spl run <you> t" in out and "spl drop theleader t" in out, out
        expose("--name", "sig", "sh", "-c", "kill -TERM $$")
        expose("--name", "who", "sh", "-c", 'echo "$SPL_PEER"; pwd')
        expose("--name", "count", "sh", "-c", "sleep 4; wc -c")
        expose("--name", "big", "head", "-c", "5000000", "/dev/zero")
        expose("--name", "yes", "yes")
        expose("--name", "nothere", "no-such-program-spl-test")
        pidfile = os.path.join(work, "pid")
        expose("--name", "hang", "sh", "-c", f'echo $$ > {pidfile}; exec sleep 60')
        expose("--name", "tty", "--pty", "sh", "-c", "tty; exit 4")
        # ignores the hang-up (and `exec sleep` keeps it ignored)
        expose("--name", "stubborn", "sh", "-c", f'trap "" HUP; echo $$ > {pidfile}; exec sleep 60')

        # --- stdout and stderr apart; input ends, output continues; the status is ours
        r = spl(lenv, "run", "thefollower", "t", input=b"hello\n")
        assert r.returncode == 3, r
        assert r.stdout == b"hello\n" and b"oops" in r.stderr and b"hello" not in r.stderr, r
        r = spl(lenv, "run", "thefollower", "sig", input=b"")
        assert r.returncode == 128 + signal.SIGTERM, r
        r = spl(lenv, "run", "thefollower", "who", input=b"", text=False)
        lines = r.stdout.decode().splitlines()
        assert r.returncode == 0 and lines == ["theleader", os.path.expanduser("~")], r
        print("  output/errors apart, exit code and signal passed through, SPL_PEER + home")

        # --- flow control: 8 MB into a program that doesn't read for 4 s, while
        # the host daemon stays responsive; then 5 MB back out
        blob = os.path.join(work, "blob")
        with open(blob, "wb") as f:
            f.write(os.urandom(8 * 1024 * 1024))
        with open(blob, "rb") as src:
            p = subprocess.Popen([SPL, "run", "thefollower", "count", *A], env=lenv, stdin=src,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(3)
            # flow control: while the program isn't reading, the sender is held back
            fdinfo = f"/proc/{p.pid}/fdinfo/0"
            if os.path.exists(fdinfo):
                pos = int(open(fdinfo).read().split("pos:")[1].split()[0])
                # (~0.7 MB: the pipe, socket and TCP windows in between; without
                # flow control it's however much the link moves in 3 s)
                assert pos < 1280 * 1024, f"read {pos} bytes ahead of a program not reading"
            t0 = time.time()
            st = spl(fenv, "status", text=True)
            assert st.returncode == 0 and time.time() - t0 < 2, "daemon stalled by a slow reader"
            o, e = p.communicate(timeout=120)
        assert p.returncode == 0 and o.strip() == str(8 * 1024 * 1024).encode(), (o, e)
        r = spl(lenv, "run", "thefollower", "big", input=b"", timeout=120)
        assert r.returncode == 0 and len(r.stdout) == 5000000 and r.stdout.count(b"\0") == 5000000
        print("  8 MB in to a slow reader (daemon responsive), 5 MB out")

        # --- `spl run … | head`: stops when our output goes away
        t0 = time.time()
        r = subprocess.run(f"'{SPL}' run thefollower yes {' '.join(A)} | head -n 3",
                           shell=True, env=lenv, capture_output=True, timeout=30)
        assert r.stdout == b"y\ny\ny\n" and time.time() - t0 < 20, r
        print("  a closed output stops the run")

        # --- a missing program fails like in a shell
        r = spl(lenv, "run", "thefollower", "nothere", input=b"")
        assert r.returncode == 127 and b"not found" in r.stderr, r

        # --- 255 is spl's own failure, never a program's
        assert spl(fenv, "inbox", "theleader", os.path.join(work, "in")).returncode == 0
        for args, why in ((["run", "thefollower", "nope"], b"isn't offered"),
                          (["run", "thefollower", "inbox"], b"receives files"),
                          (["run", "thefollower", "t", "extra"], b"fixed"),
                          (["run", "nobody", "t"], b"no peer")):
            r = spl(lenv, *args, input=b"")
            assert r.returncode == 255 and why in r.stderr, (args, r)
        print("  spl's own failures exit 255 with the reason")

        # --- the connection goes away: the program is hung up
        p = subprocess.Popen([SPL, "run", "thefollower", "hang", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert wait_for(lambda: os.path.exists(pidfile) and open(pidfile).read().strip(), 20)
        pid = int(open(pidfile).read())
        assert alive(pid)
        p.kill()  # the client vanishes
        p.wait()
        assert wait_for(lambda: not alive(pid), 10), "program outlived its connection"
        print("  a vanished client's program is stopped")

        os.remove(pidfile)
        p = subprocess.Popen([SPL, "run", "thefollower", "hang", *A], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert wait_for(lambda: os.path.exists(pidfile) and open(pidfile).read().strip(), 20)
        pid = int(open(pidfile).read())
        assert spl(fenv, "stop").returncode == 0  # the offering side goes away
        o, e = p.communicate(timeout=30)
        assert p.returncode == 255 and b"lost" in e, (p.returncode, e)
        assert wait_for(lambda: not alive(pid), 10), "program outlived its daemon"
        assert spl(fenv, "start").returncode == 0
        print("  a lost connection exits 255, and the program is stopped")

        # --- one that ignores SIGHUP is killed all the same: 5 s after its client
        # vanished, and at once when the daemon stops
        def start_stubborn():
            if os.path.exists(pidfile):
                os.remove(pidfile)
            p = subprocess.Popen([SPL, "run", "thefollower", "stubborn", *A], env=lenv,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            assert wait_for(lambda: os.path.exists(pidfile) and open(pidfile).read().strip(), 20)
            return p, int(open(pidfile).read())

        p, pid = start_stubborn()
        p.kill()
        p.wait()
        time.sleep(2)
        assert alive(pid), "SIGHUP was ignored, so it should still be in its grace period"
        assert wait_for(lambda: not alive(pid), 10), "a program ignoring SIGHUP was never killed"
        p, pid = start_stubborn()
        assert spl(fenv, "stop").returncode == 0
        p.communicate(timeout=30)
        assert wait_for(lambda: not alive(pid), 10), "a program ignoring SIGHUP outlived the daemon"
        assert spl(fenv, "start").returncode == 0
        print("  a program ignoring SIGHUP is killed (after the grace, or on spl stop)")

        # --- a PTY offer: a terminal there; `run` works on it, status passes
        r = spl(lenv, "run", "thefollower", "tty", input=b"")
        assert r.returncode == 4 and b"/dev/" in r.stdout, r
        assert spl(fenv, "revshell", "theleader").returncode == 0
        r = spl(lenv, "shell", "thefollower", input=b"exit 7\n")
        assert r.returncode == 7, r
        r = spl(lenv, "shell", "thefollower", "--name", "t", input=b"")
        assert r.returncode == 255 and b"runs a command" in r.stderr, r  # not on a terminal
        print("  PTY offers: a terminal, and the shell's exit status")

        ls = spl(lenv, "ls", "thefollower", text=True).stdout
        assert "runs a command" in ls and "spl run thefollower t" in ls, ls
        assert "spl shell thefollower --name tty" in ls, ls
        print("EXEC PASSED")
    finally:
        for env in envs:
            subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
