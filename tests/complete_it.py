#!/usr/bin/env python3
"""Completion engine: `spl __complete` returns the right candidates per position,
including daemon-backed ones (instance ids), and the bash wrapper drives it."""
import os
import subprocess
import sys
import tempfile
import time

from itlib import free_port, pair_two, start_server, stop

SPL = sys.argv[1]


def comp(env, cword, *words):
    r = subprocess.run([SPL, "__complete", str(cword), *words], env=env,
                       capture_output=True, text=True, timeout=15)
    return r.stdout.split()


def main():
    port = free_port()
    srv = start_server(SPL, port)
    lenv = fenv = None
    try:
        ld, fd = pair_two(SPL, port)
        lenv = dict(os.environ, SPL_CONFIG_DIR=ld, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        fenv = dict(os.environ, SPL_CONFIG_DIR=fd, SPL_RUNTIME_DIR=tempfile.mkdtemp())
        A = ["--server", "127.0.0.1", "--port", str(port)]

        # commands (no daemon needed)
        cmds = comp(lenv, 1, "spl")
        for c in ("serve", "get", "send", "inbox", "chat", "register", "close", "status",
                  "ping", "config"):
            assert c in cmds, f"missing command {c}: {cmds}"
        assert "peer" not in cmds, "the 'peer' prefix should be gone"
        print("  commands OK")

        # send/inbox/ping complete peer names in slot 0
        for c in ("send", "inbox", "ping"):
            assert "thefollower" in comp(lenv, 2, "spl", c), c
        print("  send/inbox/ping peer completion OK")

        # peer names from the store (no daemon)
        peers = comp(lenv, 2, "spl", "get")
        assert "thefollower" in peers, peers
        print("  peer names OK")

        # pipe TYPEs
        types = comp(lenv, 4, "spl", "register", "thefollower", "x")
        assert types == ["ECHO", "SHARE_FILE", "GET_FILE", "PIPE"], types
        # SHARE_FILE arg -> files
        assert comp(lenv, 5, "spl", "register", "thefollower", "x", "SHARE_FILE") == ["__FILES__"]
        # ECHO arg -> nothing
        assert comp(lenv, 5, "spl", "register", "thefollower", "x", "ECHO") == []
        print("  types + type-args OK")


        # daemon-backed: instance ids for `close`
        for env in (lenv, fenv):
            subprocess.run([SPL, "start", *A], env=env, capture_output=True, timeout=20)
        subprocess.run([SPL, "register", "theleader", "echo", "ECHO"], env=fenv,
                       capture_output=True, timeout=15)
        p = subprocess.Popen([SPL, "open", "thefollower", "echo"], env=lenv,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        p.stdin.write("hi\n"); p.stdin.flush(); p.stdout.readline()
        time.sleep(0.5)
        ids = comp(lenv, 3, "spl", "close", "thefollower")
        assert ids and all(i.isdigit() for i in ids), f"instance ids: {ids}"
        print(f"  instance-id completion OK ({ids})")
        p.stdin.close(); stop(p)

        # my-pipe names for `unregister` (persisted)
        mine = comp(fenv, 3, "spl", "unregister", "theleader")
        assert "echo" in mine, mine
        print("  unregister pipe-name OK")

        # remote pipe completion for `get` (the LIST verb): the follower serves
        # 'echo'; from the leader, `get thefollower <TAB>` should offer it.
        for _ in range(20):
            rp = comp(lenv, 3, "spl", "get", "thefollower")
            if "echo" in rp:
                break
            time.sleep(0.3)
        assert "echo" in rp, f"remote pipe completion: {rp}"
        print("  remote-pipe completion OK (LIST)")

        # `spl ls <peer>` shows the peer's offered pipes
        r = subprocess.run([SPL, "ls", "thefollower", *A], env=lenv,
                           capture_output=True, text=True, timeout=15)
        assert "echo" in r.stdout, f"ls <peer>: {r.stdout}"
        print("  ls <peer> OK")

        # bash wrapper actually drives it
        bashrc = os.path.join(os.path.dirname(__file__), "..", "completions", "spl.bash")
        script = f'''
        source "{bashrc}"
        COMP_WORDS=(spl get)
        COMP_CWORD=2
        _spl
        printf '%s\\n' "${{COMPREPLY[@]}}"
        '''
        r = subprocess.run(["bash", "-c", script], env=dict(lenv, PATH=os.path.dirname(SPL) + ":" + os.environ["PATH"]),
                           capture_output=True, text=True, timeout=15)
        assert "thefollower" in r.stdout, f"bash wrapper: {r.stdout}{r.stderr}"
        print("  bash wrapper OK")

        for env in (lenv, fenv):
            subprocess.run([SPL, "stop"], env=env, capture_output=True)
        print("COMPLETION PASSED")
    finally:
        for env in (lenv, fenv):
            if env:
                subprocess.run([SPL, "stop"], env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
        stop(srv)


if __name__ == "__main__":
    main()
