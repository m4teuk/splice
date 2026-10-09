#!/usr/bin/env python3
"""The daemon's socket directory fallback (${TMPDIR:-/tmp}/spl-<uid>) is only used
when it's really ours: a pre-planted symlink or non-directory makes spl refuse
loudly, while our own (even too-open) directory is tightened to 0700 and used."""
import os
import stat
import subprocess
import sys
import tempfile

from itlib import free_port

SPL = sys.argv[1]


def env_for(tmpdir, cfg):
    env = {k: v for k, v in os.environ.items() if k not in ("SPL_RUNTIME_DIR", "XDG_RUNTIME_DIR")}
    env.update(TMPDIR=tmpdir, SPL_CONFIG_DIR=cfg)
    return env


def run(args, env):
    return subprocess.run([SPL, *args], env=env, capture_output=True, text=True, timeout=30)


def main():
    cfg = tempfile.mkdtemp()
    run_name = "spl-%d" % os.getuid()

    # --- a planted symlink: refuse, and never create anything behind it ---
    base = tempfile.mkdtemp()
    target = tempfile.mkdtemp()
    os.symlink(target, os.path.join(base, run_name))
    r = run(["stop"], env_for(base, cfg))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "symlink" in r.stderr and "intercept" in r.stderr, r.stderr
    assert "daemon not running" not in r.stdout, "should refuse before touching the socket"
    assert os.listdir(target) == [], "nothing may be created through the symlink"
    print("  planted symlink -> refused")

    # --- a planted regular file: refuse ---
    base = tempfile.mkdtemp()
    open(os.path.join(base, run_name), "w").close()
    r = run(["stop"], env_for(base, cfg))
    assert r.returncode == 1 and "not a directory" in r.stderr, r.stderr
    print("  planted file -> refused")

    # --- our own dir, but too open: tightened to 0700, daemon runs in it ---
    base = tempfile.mkdtemp()
    d = os.path.join(base, run_name)
    os.mkdir(d)
    os.chmod(d, 0o777)
    env = env_for(base, cfg)
    r = run(["start", "--server", "127.0.0.1", "--port", str(free_port())], env)
    try:
        assert r.returncode == 0, r.stdout + r.stderr
        assert stat.S_IMODE(os.lstat(d).st_mode) == 0o700, oct(os.lstat(d).st_mode)
        assert os.path.exists(os.path.join(d, "daemon.sock"))
        print("  own loose dir -> tightened to 0700 and used")
    finally:
        r = run(["stop"], env)
    assert r.returncode == 0 and "daemon stopped" in r.stdout, r.stdout + r.stderr
    print("OK")


if __name__ == "__main__":
    main()
