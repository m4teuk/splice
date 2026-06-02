# Deploying a splice relay server

A production relay is a single binary run by systemd as an unprivileged user,
binding `:443` (TCP for pairing + UDP for the relay/hole-punch) with a real
Let's Encrypt certificate. The host needs **no copy of the source repo** and the
service **never runs as root** and **never reads the private key directly**.

The example domain below is `splice.kussowski.dev`; substitute your own.

## 1. Put the binary on the host

The quickest path is a prebuilt binary — it links OpenSSL statically, so it needs
no `libssl` on the host, just the system C runtime:

```sh
curl -fsSL -o spl \
  https://github.com/m4teuk/splice/releases/download/nightly/spl-linux-x86_64
# (or spl-linux-aarch64); verify against the matching .sha256, then:
sudo install -m 0755 spl /usr/local/bin/spl
```

Otherwise build it. The repo is only needed to *build*; only the binary needs to
live on the server. Either build on the box and keep the source in root's home (not
the service user's), or build elsewhere and copy the single binary — a from-source
build needs a matching `libssl` at runtime (same OpenSSL major version) unless you
link it statically as the release binaries do.

```sh
# on the build host (needs: cmake ninja-build libssl-dev pkg-config rust)
git clone <repo> splice && cd splice
git submodule update --init --recursive
cmake -S . -B build -G Ninja && cmake --build build
sudo cmake --install build --prefix /usr/local      # -> /usr/local/bin/spl
# you can now delete the source tree; the running user just needs the binary
```

`/usr/local/bin/spl` is root-owned and mode 755 — readable and runnable by
everyone, which is fine (the binary holds no secrets). Nothing else is shared.

## 2. Get a certificate

`certbot --standalone` answers the ACME challenge on **port 80** (HTTP-01), so it
does **not** clash with splice on 443. Make sure port 80 is free during issuance.

```sh
sudo certbot certonly --standalone -d splice.kussowski.dev \
  --deploy-hook "systemctl restart splice"
```

The `--deploy-hook` is saved into the renewal config, so it also runs on every
future auto-renewal (see step 5).

> Why `restart`, not `reload`: the service receives its certs through systemd's
> `LoadCredential=`, which is read once at start. A restart re-reads the freshly
> renewed files; a reload would keep serving the old cert. The relay is stateless,
> so a restart is a sub-second blip — peers simply re-register.

## 3. Install the service

```sh
sudo cp deploy/splice.service /etc/systemd/system/
# edit the two LoadCredential= lines if your domain differs
sudo systemctl daemon-reload
sudo systemctl enable --now splice
systemctl status splice
journalctl -u splice -f          # 'splice server up: pairing tcp/443, relay udp/443'
```

How the unit solves the two hard parts:

- **Privileged port without root** — `AmbientCapabilities=CAP_NET_BIND_SERVICE`
  lets the unprivileged process bind 443 (covers both the TCP and UDP binds).
- **Cert access without exposing the key** — `LoadCredential=` makes systemd (root)
  copy `fullchain.pem`/`privkey.pem` into a per-service tmpfs readable only by the
  service; `ExecStart` points `--cert %d/cert --key %d/key` at them (`%d` =
  `$CREDENTIALS_DIRECTORY`). The key keeps its root-only `/etc/letsencrypt` perms.

`DynamicUser=yes` means you don't even create a `splice` account — systemd spins up
a transient unprivileged user for the lifetime of the service.

## 4. Open the firewall

```sh
sudo ufw allow 443/tcp     # pairing (TLS)
sudo ufw allow 443/udp     # relay + whereami + hole-punch
```

## 5. Automatic renewal

certbot installs a timer that runs `certbot renew` twice daily; on an actual
renewal it fires the saved `--deploy-hook`, which restarts splice onto the new
cert. Verify the whole path without waiting ~60 days:

```sh
sudo certbot renew --dry-run
systemctl list-timers certbot.timer
```

## 6. Point clients at it

Clients now reach a properly authenticated server (no `--insecure`):

```sh
spl pair --server splice.kussowski.dev --port 443
```

…or, in each client's `~/.config/spl/config`:

```ini
[peer]
addr = splice.kussowski.dev
port = 443
```

## Tuning rate limits (optional)

`ExecStart` passes only bind/port/cert/key, so the rate limits use their built-in
defaults. To change them, drop a config the service can read and point it there:

```sh
sudo install -d -m 755 /etc/splice
sudo tee /etc/splice/config >/dev/null <<'EOF'
[server]
per_ip_rate = 1000
per_ip_burst = 2000
global_rate = 200000
global_burst = 400000
EOF
```

Then add `Environment=SPL_CONFIG_DIR=/etc/splice` to the unit (the `--cert`/`--key`
flags still override anything in the file) and `systemctl restart splice`.
