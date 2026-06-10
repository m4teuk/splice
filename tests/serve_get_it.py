#!/usr/bin/env python3
"""serve/get integration: SHARE_FILE/GET_FILE pipes through two daemons."""
import hashlib
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, start_server, stop, pair_two

SPL = sys.argv[1]


def env_for(cfg, run):
    return dict(os.environ, SPL_CONFIG_DIR=cfg, SPL_RUNTIME_DIR=run)


def spl(env, *args, **kw):
    kw.setdefault("stdout", subprocess.PIPE)
    kw.setdefault("stderr", subprocess.STDOUT)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 60)
    return subprocess.run([SPL, *args], env=env, **kw)


def sha(p):
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def main():
    port = free_port()
    server = start_server(SPL, port)
    try:
        ld, fd = pair_two(SPL, port)
        lrun, frun = tempfile.mkdtemp(), tempfile.mkdtemp()
        lenv, fenv = env_for(ld, lrun), env_for(fd, frun)
        largs = ["--server", "127.0.0.1", "--port", str(port)]

        # the follower serves a 3MB random file
        src_dir = tempfile.mkdtemp()
        src = os.path.join(src_dir, "blob with spaces.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(3 * 1024 * 1024))

        r = spl(fenv, "serve", "theleader", "--name", "blob", src, *largs)
        assert r.returncode == 0, f"serve failed:\n{r.stdout}"
        assert "as 'blob'" in r.stdout

        # the leader fetches it (foreground), name comes from the header
        dl = tempfile.mkdtemp()
        r = spl(lenv, "get", "thefollower", "blob", "-o", dl, *largs)
        assert r.returncode == 0, f"get failed:\n{r.stdout}"
        got = os.path.join(dl, "blob with spaces.bin")
        assert os.path.exists(got), r.stdout
        assert sha(got) == sha(src), "content mismatch"
        print("  foreground get OK (3MB, spaces in name)")

        # refuses to overwrite; -f allows it
        r = spl(lenv, "get", "thefollower", "blob", "-o", dl, *largs)
        assert r.returncode != 0 and "exists" in r.stdout, r.stdout
        r = spl(lenv, "get", "thefollower", "blob", "-o", dl, "-f", *largs)
        assert r.returncode == 0, r.stdout
        print("  overwrite rules OK")

        # background get (daemon-owned GET_FILE)
        dl2 = tempfile.mkdtemp()
        r = spl(lenv, "get", "thefollower", "blob", "-o", dl2, "--background", *largs)
        assert r.returncode == 0, r.stdout
        deadline = time.time() + 30
        got2 = os.path.join(dl2, "blob with spaces.bin")
        while time.time() < deadline and not os.path.exists(got2):
            time.sleep(0.3)
        assert os.path.exists(got2), spl(lenv, "peer", "status").stdout
        assert sha(got2) == sha(src), "background content mismatch"
        print("  background get OK")

        # the serve survives a daemon restart (registration is on disk)
        assert spl(fenv, "peer", "stop").returncode == 0
        assert spl(fenv, "peer", "start", *largs).returncode == 0
        dl3 = tempfile.mkdtemp()
        deadline = time.time() + 30
        while time.time() < deadline:
            r = spl(lenv, "get", "thefollower", "blob", "-o", dl3, *largs)
            if r.returncode == 0:
                break
            time.sleep(0.5)
        assert r.returncode == 0, r.stdout
        assert sha(os.path.join(dl3, "blob with spaces.bin")) == sha(src)
        print("  serve survived daemon restart")

        # getting an unknown pipe fails cleanly
        r = spl(lenv, "get", "thefollower", "nope", *largs)
        assert r.returncode != 0, r.stdout
        print("  unknown pipe fails cleanly")

        for env in (lenv, fenv):
            spl(env, "peer", "stop")
        print("serve/get integration: all OK")
    finally:
        stop(server)


if __name__ == "__main__":
    main()
