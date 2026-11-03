# multihop-ansible

Ansible project that deploys a two-hop VPN: an entry server managed from the Amnezia app (AmneziaWG, optionally the app's Xray as well), an uplink to an exit server (AWG, or VLESS + REALITY), split routing on the entry, encrypted S3 backups of the user state, and playbooks to swap either server.

## What this is

Uplink `awg` (default): everything bridge-side goes into the AWG uplink.

```
 user (Amnezia app) ──AWG 3.1──▶ ENTRY (country A)                  EXIT (country B)
   endpoint: entry.<domain>      ┌──────────────────────────┐       ┌──────────────────────┐
                                 │ container amnezia-awg2   │       │ container            │
                                 │  (app-managed users)     │       │ multihop-exit        │
                                 │  NAT → docker0 / amn0    │       │  AWG 3.1 server,     │
                                 └────────────┬─────────────┘       │  one peer: entry     │
                                              │ policy routing      │  NAT → internet      │
                                 ┌────────────▼─────────────┐       └──────────▲───────────┘
                                 │ container multihop-uplink│──AWG 3.1───────┘
                                 │  (host network) iface    │   endpoint: exit.<domain>
                                 │  awg-uplink              │
                                 └──────────────────────────┘
```

Uplink `reality` (`uplink_transport: reality`): no tunnel interface. The entry hands each TCP connection and UDP flow to Xray with TPROXY, and Xray carries it to the exit over VLESS + REALITY (`flow: xtls-rprx-vision`, TCP on `exit_reality_port`). The exit's Xray connects out to the internet itself (`freedom`).

```
 user ──AWG 3.1──▶ ENTRY (country A)                                    EXIT (country B)
 user ──VLESS+REALITY──▶ ┌────────────────────────────────┐
   (optional, app Xray)  │ amnezia-awg2 / amnezia-xray    │
                         │  bridge traffic, not direct/   │
                         │  reply/local → TPROXY, else    │
                         │  DROP (MULTIHOP-TPROXY)        │
                         └───────────────┬────────────────┘
                                         ▼ 127.0.0.1:<uplink_tproxy_port>
                         ┌───────────────────────────────┐   VLESS + REALITY    ┌─────────────────────────┐
                         │ multihop-uplink-xray          │══════════════════════▶ multihop-exit-xray      │
                         │  (host network, only outbound │  exit.<domain>:      │  inbound VLESS+REALITY  │
                         │   is the VLESS one)           │  exit_reality_port   │  outbound freedom →     │
                         └───────────────────────────────┘                      │  internet               │
                                                                                └─────────────────────────┘
```

The exit's `multihop-exit` (AWG) keeps running in `reality` mode, so going back to `awg` needs only an entry deploy.

- Ansible builds the entry exactly like the app would (container `amnezia-awg2`, network `amnezia-dns-net`), so the app adopts it. Users are then managed in the app. Ansible never writes `clientsTable`.
- The entry's user state is a host bind mount (`/var/lib/multihop/entry-awg`) and is backed up (age-encrypted, change-only) to S3.
- With `entry_xray_enabled`, the entry also runs the app's Xray server (container `amnezia-xray`, VLESS + REALITY) next to `amnezia-awg2`. It is adopted and managed by the app the same way; its state is the bind mount `/var/lib/multihop/entry-xray`, backed up with the AWG state. Xray users take the same route out as AWG users.
- Traffic from users goes through the exit. Destinations on the split-routing direct list (default: country `ru` plus your own lists) leave straight from the entry.
- Fail-closed: if the exit or the uplink is down, users lose internet; nothing leaks out of the entry's public IP (except the direct split list, by design). In `reality` mode a bridge packet takes exactly one way: reply-marked or direct-marked (as before), to a local or bridge address (normal routing), TCP/UDP to Xray via TPROXY, or DROP (other protocols such as ICMP). If Xray is not listening, TPROXY drops; if a rule is missing, the packet is delivered locally to a socket that does not exist or hits the blackhole in table 51820. Xray's only outbound is the VLESS one to the exit.
- Both servers run BBR (`net.ipv4.tcp_congestion_control=bbr` with `fq`, `tcp_bbr` loaded at boot); it matters for the TCP-based `reality` uplink.
- Re-running playbooks is safe: users added in the app are kept.

Ansible-owned things never match `grep amnezia` except `amnezia-awg2`, `amnezia-xray` and `amnezia-dns-net`: own containers are `multihop-uplink` / `multihop-uplink-xray` / `multihop-exit` / `multihop-exit-xray`, host state is under `/var/lib/multihop/`.

### What users notice in `reality` mode

- No ICMP through the VPN: `ping` from a user device gets no reply (the entry drops everything that is not TCP or UDP).
- QUIC (UDP 443) falls back to TCP/TLS: Vision refuses UDP to port 443. Browsers switch on their own.
- Each new connection costs about 2 extra round trips to the exit (one REALITY handshake; ~75 ms on a Moscow to Frankfurt route). Mux is not used (incompatible with Vision).
- Measured in the gate on that route (2026-11-03, BBR): the AWG uplink gave about 1.5 Mbit/s, Xray-only about 195 Mbit/s (the exit's plan limit). Details in `docs/superpowers/specs/2026-11-03-xray-only-uplink-addendum.md`.

## Requirements

Controller (macOS or Linux):

- `uv` (Python deps and Ansible are installed from `pyproject.toml` via `uv run`)
- Ansible collections: `make collections`
- `age` (decrypts backups) and AWS CLI v2 (fetches them)
- `dig` (the DNS step checks resolvers)
- development only: `bats-core`, `shellcheck` (`make test lint`)

Servers: two Ubuntu 24.04 hosts with SSH and sudo. Set `ansible_host` of the entry and exit to their **public IPv4 address**. Only the swap playbooks assert this; the DNS step simply uses `ansible_host` as the record's IP and `site.yml` does not check it, but it must be the public IPv4 either way.

S3: a **dedicated bucket** with **versioning enabled** (enable it in the provider; the entry's writer key can overwrite or delete objects, versioning is what covers that). Two credential sets: a writer (goes on the entry) and a reader (controller only). They can be the same key if the provider cannot separate them.

Minimal key policies (tested on Timeweb Cloud S3): writer `PutObject`, `AbortMultipartUpload`, `ListMultipartUploadParts` on `<bucket>/<prefix>/*` plus `GetBucketVersioning` on the bucket; reader `GetObject`, `GetObjectVersion` on the prefix plus `ListBucket`, `ListBucketVersions`, `GetBucketVersioning` on the bucket. The AWS CLI's default addressing (path-style with `--endpoint-url`) works there, and so does virtual-hosted. `entry.yml` prints a warning when `get-bucket-versioning` does not report `Enabled`. On that provider a denied request returns an empty error message, which AWS CLI 2.39 reports as `argument of type 'NoneType' is not a container or iterable` instead of `AccessDenied`.

## First deploy

1. Copy the inventory and edit it:

   ```bash
   cp -r inventories/example inventories/prod
   $EDITOR inventories/prod/hosts.yml inventories/prod/group_vars/all/vars.yml
   ```

   In `hosts.yml` set `ansible_user` (a user with sudo) and your SSH key setup (`ansible_ssh_private_key_file` or an agent), and `ansible_port` / `ssh_port` if SSH is not on 22 (`ssh_port` also opens it in the host firewall). Set `entry_domain`, `exit_domain`, ports, `backup_*` (except `backup_age_recipient`, which comes after step 3), `awg_base_image_digest` and `xray_image_digest` (see "Updating the pinned images"), and the transport variables in "Uplink and Xray variables". Point `inventory` in `ansible.cfg` at it or pass `-i inventories/prod`.

2. Vault password: put it in `.vault-pass` (gitignored; `ansible.cfg` reads it) or set `ANSIBLE_VAULT_PASSWORD_FILE`.

3. Generate the secrets, fill in the S3 and age fields, encrypt:

   ```bash
   uv run scripts/gen-secrets.py all > inventories/prod/group_vars/all/vault.yml
   uv run scripts/gen-secrets.py uplink-key > inventories/prod/group_vars/all/vault_uplink.yml
   mkdir -p ~/.config/multihop && age-keygen -o ~/.config/multihop/age.key   # prints the public key; keep the key out of the repo
   $EDITOR inventories/prod/group_vars/all/vault.yml
   uv run ansible-vault encrypt inventories/prod/group_vars/all/vault.yml inventories/prod/group_vars/all/vault_uplink.yml
   ```

   In `vault.yml` replace the `CHANGE_ME` values: `vault_backup_writer`, `vault_backup_reader`, and `vault_backup_age_identity` (the `AGE-SECRET-KEY-...` line from `~/.config/multihop/age.key`). Only now put the age **public** key (printed by `age-keygen`) in `vars.yml` as `backup_age_recipient`. The first line of the generated file suggests random ports for `entry_awg_port` / `exit_awg_port`. Each link gets its own random AmneziaWG 3.1 obfuscation values (Jc/Jmin/Jmax, S1–S4, non-overlapping H1–H4 ranges, a DNS-query I1) instead of the app's shared defaults; existing vaults keep their values. See `inventories/example/group_vars/all/vault.yml.example` for the structure (fake values). `vault_uplink.yml` holds `vault_uplink_entry` (the entry's AWG uplink key and its `reality_uuid`) and is kept separate because swap-entry rotates it. `gen-secrets.py all` also writes the two Xray blocks: `vault_link_reality` (`private_key`, `public_key`, `short_id`: the exit's REALITY identity) and `vault_entry_xray` (`uuid`, `private_key`, `public_key`, `short_id`: seeds the app's Xray server on the first deploy only). Both are needed only with `uplink_transport: reality` / `entry_xray_enabled: true`.

   **Existing vault, adding the Xray blocks** (nothing is written to disk in plaintext; put the output on the clipboard and paste it in the editor that `ansible-vault edit` opens, which keeps its temporary file private and removes it on exit):

   ```bash
   uv run scripts/gen-secrets.py xray | pbcopy        # Linux: xclip -selection clipboard
   uv run ansible-vault edit inventories/prod/group_vars/all/vault.yml   # paste at the end, save
   ```

   `vault_uplink.yml` needs `reality_uuid` inside `vault_uplink_entry`. Regenerating it gives one, but it also **rotates the AWG uplink key**, so deploy the exit first and then the entry (a few minutes without internet for users while the two disagree):

   ```bash
   uv run scripts/gen-secrets.py uplink-key | uv run ansible-vault encrypt --output inventories/prod/group_vars/all/vault_uplink.yml -
   uv run ansible-playbook playbooks/exit.yml && uv run ansible-playbook playbooks/entry.yml
   ```

   To keep the AWG key, add only the line `reality_uuid: <a UUID v4>` to `vault_uplink_entry` with `ansible-vault edit` instead. The playbooks refuse to run in `reality` mode when a block or `reality_uuid` is missing and print the command above.

   Before switching an existing entry to `reality`, check that its kernel has TPROXY: `ssh root@<entry> modprobe xt_TPROXY` must succeed. `entry.yml` loads `xt_TPROXY` and `nf_tproxy_ipv4` itself (and on boot, from `/etc/modules-load.d/multihop-tproxy.conf`) and stops before changing anything if it cannot, but the exit (deployed first) would already be switched.

4. Create DNS A records for `entry_domain` and `exit_domain` pointing at the servers, with a **low TTL (60-300 s)**. The exit swap and the entry re-resolve timer rely on it.

5. Install collections and deploy:

   ```bash
   make collections
   uv run ansible-playbook playbooks/site.yml    # exit, then entry, then verify
   ```

Individual playbooks: `exit.yml`, `entry.yml`, `verify.yml`, `backup.yml` (on-demand backup), `restore.yml`, `swap-exit.yml`, `swap-entry.yml`.

Check the path any time:

```bash
uv run ansible-playbook playbooks/verify.yml
uv run ansible-playbook playbooks/verify.yml -e verify_fail_closed=true   # or --tags fail_closed
```

The fail-closed test stops the uplink container (`multihop-uplink`, or `multihop-uplink-xray` in `reality` mode) and checks that `amnezia-awg2` (and `amnezia-xray`, when enabled) cannot reach the internet. In `reality` mode `verify.yml` also checks that `multihop-uplink-xray` listens on the TPROXY port, that the egress IP is the exit's, and that the exit sees an established connection from the entry on `exit_reality_port`. It interrupts users for about a minute. Optional: `-e verify_ip_echo_url=...` (default `https://api.ipify.org`).

## Adding the server in the Amnezia app

Add the server by **domain** (`entry_domain`) with an SSH user that has sudo. The app detects AmneziaWG as already installed (expected to show "version 3.1": the Amnezia client labels a server that way when its `awg0.conf` carries the 3.1 options such as `HeaderProtectionKey` and `RekeyAfterTime`, which this setup writes; see `hasAwg3Markers` in amnezia-client `awgProtocolConfig.cpp`; expected behaviour, not a guarantee). Then add users and share keys as usual.

## Rules for the entry

- The entry runs exactly `amnezia-awg2`, `amnezia-xray` (only with `entry_xray_enabled`) and one uplink container: `multihop-uplink` (`awg` mode) or `multihop-uplink-xray` (`reality` mode). Do not add other containers to its Docker bridges: the fail-closed exceptions for the AWG server's and the Xray server's replies assume these two are the only senders from `entry_awg_port` and `entry_xray_port` on `docker0`/`amn0`.
- **Do not use the app's "remove / reinstall protocol", and do not edit AmneziaWG settings in the app.** The app reinstalls the container: new server keys, an empty user list, and our bind mount and the fixed NAT port range are gone. Every issued key stops working.
- Reinstalling also removes the container's fixed NAT port range, the basis of the AWG UDP reply exception, so user UDP from source port `entry_awg_port` could then leave via the entry's own IP.
- Drift detection: the backup timer checks every run that `amnezia-awg2` still has the bind mount, and with `entry_xray_enabled` that `amnezia-xray` still bind-mounts `/var/lib/multihop/entry-xray` (the app's reinstall puts its named volume there instead). If not, `multihop-backup` writes `/var/lib/multihop/backup/DRIFT` (one line per drifted container), still backs up the host state directories (they hold the last good state, and drift on one protocol must not stop the other's backup), and exits with code 2; `entry.yml` fails with recovery instructions. Look for it with `systemctl status multihop-backup.service` and `journalctl -u multihop-backup`.

## Xray in the app (`entry_xray_enabled`)

Set `entry_xray_enabled: true` and deploy `entry.yml`: it builds `amnezia-xray` from the app's own Dockerfile (pinned base, as for AWG) with a bind-mounted state directory, seeds `server.json` and the key files from `vault_entry_xray` (first deploy only), and publishes `entry_xray_port` (TCP). The app then adopts it like `amnezia-awg2`.

Rules, in addition to the entry rules above:

- Manage the Xray server **only from the macOS Amnezia app 5.1.0.6**, the version this was built against. Older apps write the Xray server config differently.
- Adding and removing Xray users in the app is the normal path. Changing the REALITY **site** in the app is allowed: the app rewrites `server.json` in its own shape, which the backup validation accepts.
- **Do not change the Xray port in the app.** The published port, the firewall and the reply exception are built from `entry_xray_port`; `entry.yml` refuses to run when `server.json` has another port.
- **Do not use "remove / reinstall protocol" for Xray.** The app recreates the container on a named volume (drift) with new keys, so every issued Xray key stops working. Same as AWG.
- Open point, not yet verified: app 5.1.0.6 expects server Xray `v26.7.28` (`expectedServerXrayRelease`), while the vendored Dockerfile installs `v26.10.31`. Whether the app adopts such a server silently or offers an update or reinstall is to be checked on a lab entry with the real app. Until that is recorded in the design document (section 5), do not accept an update or reinstall offer for Xray.

Clients:

- AWG users change nothing: their keys and apps, including the standalone AmneziaWG app, keep working.
- Xray users need a **VLESS + REALITY client**; the AmneziaWG app cannot be used. For each Xray user the Amnezia app exports a `vless://` link or an Xray JSON config. Any standard client takes either: for example Streisand, V2Box, Hiddify or Happ on iOS, v2rayNG, Hiddify or Happ on Android, Hiddify or v2rayN on desktop. Example (shape only, the app fills the fields): `vless://<uuid>@entry.<domain>:<entry_xray_port>?security=reality&sni=<site>&pbk=<public key>&sid=<short id>&flow=xtls-rprx-vision&type=tcp#<name>`.

## Operator constraints

- `entry.yml` needs a working exit: the `amnezia-awg2` image build (and any traffic from the entry's containers) goes through the uplink.
- `entry_awg_port` and `entry_awg_subnet` cannot change after the first deploy: `awg0.conf` is written only when absent, and a restore refuses a backup with another port or subnet. The same holds for `entry_xray_port`: `entry.yml` refuses to run when the entry's `server.json` has another port, and a restore refuses an `xray/server.json` with another port.
- Docker on the entry does not start if the routing and firewall rules cannot be applied (`ExecStartPre=multihop-entry-net up`): fail-closed rather than forwarding through the entry's IP. Check `systemctl status docker` and `journalctl -u docker` if it stays down; after fixing the cause run `systemctl reset-failed docker docker.socket && systemctl start docker` (systemd stops retrying after a few failed starts). In `reality` mode there are more ways for `up` to fail, by design: the TPROXY target is missing (`entry.yml` loads `xt_TPROXY` and `nf_tproxy_ipv4` before any change and `/etc/modules-load.d/multihop-tproxy.conf` loads them on boot, so this takes e.g. a new kernel without them; check with `modprobe xt_TPROXY`), or `ENTRY_LOCAL_NETS` in `/etc/multihop/multihop.env` is empty (the script then refuses, because bridge-to-bridge traffic would be proxied). Fix the cause and run the two commands above.
- Traffic from the entry's containers may leave only through the uplink, the public interface (direct split list and the AWG server's own UDP), or another Docker bridge. Anything to other NICs (e.g. a provider private network) is dropped. The exit also drops user traffic to private, CGNAT and link-local ranges (provider metadata).
- `uplink_transport: reality` needs TCP `exit_reality_port` reachable on the exit and the exit's AWG port left open (see "Swap the exit" and rollback). `uplink_tproxy_port` is loopback only; it must differ from `entry_xray_port` and the SSH port.
- After an entry swap with the old entry unreachable, retire the old entry if it comes back: stop `amnezia-awg2` and `multihop-uplink` and disable `multihop-backup.timer`. Its backup timer can otherwise overwrite `latest`.
- Old entry reachable, but its final backup fails (e.g. drift after an app reinstall): fix it first (`restore.yml` against the old entry, then retry the swap), or deliberately take the unreachable path (power it off) and accept losing users added since the last good backup.
- Keep these outside the repository and back them up: the vault files, the vault password and the age identity. The vault is the only copy of the exit identity and the entry-uplink key; without the age identity no backup can be restored.
- The vendored app Dockerfile keeps the app's `apk add` / `apk upgrade` steps (parity with the app). Only the base image is pinned, so the apk layer can change whenever the image is rebuilt.

## Recovery

Replace the entry's user state with the latest backup (also the fix after an app reinstall). Users added after that backup are lost:

```bash
uv run ansible-playbook playbooks/restore.yml                      # asks for confirmation
uv run ansible-playbook playbooks/restore.yml -e confirm=yes
```

Restore an older backup (names are the object keys under `<backup_s3_prefix>/`, e.g. `entry-<timestamp>.tar.age`; list with `aws s3 ls --endpoint-url <endpoint> s3://<bucket>/<prefix>/`):

```bash
uv run ansible-playbook playbooks/restore.yml -e backup_object=entry-<timestamp>.tar.age
```

The backup is fetched with the reader credentials, decrypted locally with the age identity from the vault, validated, pushed to the entry and deleted from the controller. Backup content wins over vault values.

With `entry_xray_enabled` the backup also holds the Xray state under `xray/` (`server.json`, `clientsTable` and the four `xray_*.key` files), and `restore.yml` restores it too. A backup without `xray/` (older, or made before Xray was enabled) restores only the AWG state and leaves the Xray state as it is, or seeds it from `vault_entry_xray` if there is none. A backup with `xray/` restored while Xray is disabled skips it with a notice. `restore.yml` therefore cannot repair Xray drift from a backup that has no `xray/` directory: either restore a newer backup that has one, or re-seed by hand (drift of either container still backs up the host state and exits 2, see the drift rule above).

Validation refuses any archive member that is not a regular file directly at the archive root or directly in `xray/` under one of those six names, and any `awg0.conf` key outside the AmneziaWG allow-list (no `PreUp`/`PostUp`/`PreDown`/`PostDown`, `SaveConfig`, `Table`, `DNS`; awg-quick would run hooks as root). It also requires `ListenPort` = `entry_awg_port` and `Address` inside `entry_awg_subnet`. `xray/server.json` must have exactly the app's shape: `log` with only a log level, one VLESS + REALITY inbound on `entry_xray_port`, and only a plain `freedom` outbound (no `routing`, `api`, `stats` or other sections, no other inbounds or outbounds); the inbound port must equal `entry_xray_port`, its REALITY `dest` must be a public site name on port 443 (`<site>:443`, never loopback or an address), duplicate JSON keys are refused, and the key files must be single-line values of the right form. age does not prove who wrote a backup, and the entry's writer key can upload one, so if the old entry may have been compromised, restore a `backup_object` from before the compromise instead of `latest`. After a reinstall, the app may have to be re-pointed at the server (same domain, nothing else changes).

## Swap the exit

The exit's identity is entirely in the vault, so a new exit is identical and the entry needs no change.

1. In the inventory put the **new** host in `exit` (`ansible_host` = its public IPv4); optionally the old one in `exit_old`.
2. Run:

   ```bash
   uv run ansible-playbook playbooks/swap-exit.yml                 # leaves the old exit running
   uv run ansible-playbook playbooks/swap-exit.yml -e stop_old=yes # also stops the old exit
   ```

It deploys the exit and updates the DNS record for `exit_domain` (manual backend: it asks you to change the record and waits until resolvers return the new IP). Then the entry flushes its resolver cache (`resolvectl flush-caches`) and:

- **`awg` mode:** the old exit's `multihop-exit` is stopped right after the DNS change (it has the same identity and would pull the entry's peer endpoint back by roaming). The playbook waits for the entry's re-resolve timer (about 1 minute plus TTL) to flip the endpoint, forces a handshake, verifies. With `stop_old=yes` the old exit's restart policy is also set to `no`, so it stays down after a reboot.
- **`reality` mode:** the entry restarts `multihop-uplink-xray` (it resolves `exit_domain` at start), then waits up to 5 minutes for an established TCP connection to the new exit on `exit_reality_port` and verifies. The old exit is not involved; `stop_old=yes` stops `multihop-exit` and `multihop-exit-xray` there at the end and disables their restart.

In `reality` mode `multihop-exit` (AWG) keeps running on the exit and its AWG port stays open to the public. That is deliberate: rolling back to `uplink_transport: awg` then needs only `entry.yml`, nothing on the exit. The entry's `multihop-reresolve` timer also restarts `multihop-uplink-xray` when the resolved exit IP changes.

## Swap the entry

1. Put the **new** host in `entry` and the **old** one in `entry_old` (one host each, public IPv4 `ansible_host`; the new entry must be a different host).
2. Run (asks for confirmation; skip with `-e confirm=yes`):

   ```bash
   uv run ansible-playbook playbooks/swap-entry.yml
   ```

- **Old entry reachable:** takes a final backup, stops the old app, uplink and backup timer (they stay stopped across reboots), then restores exactly that backup on the new entry. No users are lost.
- **Old entry unreachable:** rotates the entry-uplink key into `vault_uplink.yml`, redeploys the exit so it accepts only the new key, and restores `latest`. Users added after the last backup are lost. Keep the rewritten `vault_uplink.yml`. This step needs a vault password **file** (`.vault-pass` or `ANSIBLE_VAULT_PASSWORD_FILE`); `--ask-vault-pass` is not supported.

Both cases then deploy the entry, update the DNS record for `entry_domain`, and verify. `-e backup_object=entry-<ts>.tar.age` restores a specific backup; in the reachable case it overrides the pinned final backup and can discard users added since that backup. After the swap, update the server in the app only if it was added by IP; by domain nothing changes.

## Manual rekey of the entry protocol parameters

There is no rekey playbook, and this wipes all users. The rendered `awg0.conf` contains only `[Interface]`, so recreating it drops every peer the app added; the running server also keeps the old parameters until the container restarts (`start.sh` runs `awg-quick` only at container start).

1. Edit `params` in `vault_entry_awg`.
2. On the entry, delete `/var/lib/multihop/entry-awg/awg0.conf` **and** `/var/lib/multihop/entry-awg/clientsTable` (otherwise the app's user list goes stale). All users are gone and every issued key is invalid.
3. `uv run ansible-playbook playbooks/entry.yml`
4. On the entry: `docker restart amnezia-awg2`
5. Re-create the users in the app and re-share their keys. The next backup captures the new state.

## Uplink and Xray variables

In `group_vars/all/vars.yml` (the example inventory has them commented out or set):

| Variable | Default | Meaning |
|---|---|---|
| `uplink_transport` | `awg` | `awg`: AWG uplink as before. `reality`: TPROXY into Xray, VLESS + REALITY to the exit (needs `vault_link_reality`, `reality_uuid`) |
| `exit_reality_port` | `443` | exit's TCP port for the REALITY inbound (`reality` mode) |
| `uplink_reality_site` | `dl.google.com` | site the uplink REALITY imitates (TLS 1.3 + H2, no redirect; passed `xray tls ping` from the exit) |
| `uplink_tproxy_port` | `12345` | loopback port of the entry Xray's TPROXY inbound; must differ from `entry_xray_port` and SSH |
| `entry_xray_enabled` | `false` | run the app's Xray (`amnezia-xray`) on the entry |
| `entry_xray_port` | `443` | its TCP port; cannot change after the first deploy |
| `entry_xray_site` | `www.googletagmanager.com` | REALITY site of the seeded `server.json` (role default of `entry_xray`; the app may change it later) |
| `entry_xray_state_dir` | `/var/lib/multihop/entry-xray` | host bind mount of the Xray state (role default, normally untouched) |
| `xray_image_digest` | set in the example inventory | `ghcr.io/xtls/xray-core` pinned by digest (see below) |
| `vault_link_reality`, `vault_entry_xray` | vault | see "First deploy" |

Switching `uplink_transport` later: deploy the exit, then the entry (`exit.yml`, `entry.yml`). On the entry this replaces the uplink container (`multihop-uplink` or `multihop-uplink-xray`, never both) and the rules.

## Split routing variables

In `group_vars/all/vars.yml`:

| Variable | Meaning |
|---|---|
| `split_routing_enabled` | `true`/`false`; off sends everything through the exit |
| `split_direct_countries` | country codes whose IP ranges leave directly from the entry (example inventory value `[ru]`; the role default is empty) |
| `split_country_list_url` | list source, `{cc}` is the country code |
| `split_direct_cidrs` | extra networks that go direct |
| `split_direct_domains` | domains whose addresses go direct (re-resolved every 10 min) |
| `split_force_exit_cidrs` | networks forced through the exit even if they are in a direct list |

Country lists refresh every 24 h. A failed or garbage download keeps the previous set. Apply changes with `uv run ansible-playbook playbooks/entry.yml`. Other useful variables: `extra_input_tcp_ports` (extra open TCP ports in the host firewall), `uplink_mtu` (example inventory value 1280; no role default), `backup_interval` (default `15min`).

## DNS

`dns_backend` defaults to `manual`: the swap playbooks ask you to set the record (A, TTL 60-300) and then wait until `1.1.1.1` and `8.8.8.8` return the new IP (`dig` on the controller).

To add a provider backend, create `roles/dns_update/tasks/backend_<name>.yml` and set `dns_backend: <name>`. It receives `dns_record` (fqdn) and `dns_ip`. The role verifies resolution afterwards, so the backend only has to make the change.

`dns_backend: hostsfile` is a lab/testing backend (used by the cloud-lab integration test): instead of a DNS record it writes `<dns_ip> <dns_record>` into `/etc/hosts` on the hosts in `dns_hostsfile_hosts` (default: the `entry` group), where `multihop-reresolve` resolves the exit domain, and skips the public-resolver check. Do not use it in production. The pinned line stays in `/etc/hosts` when you switch to another backend and shadows real DNS for that name; delete it by hand.

## Updating the pinned images

The base image `amneziavpn/amneziawg-go` is pinned by digest in `awg_base_image_digest`:

```bash
curl -s https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags/latest | jq -r .digest
```

Put the `sha256:...` value into `vars.yml` and re-run `exit.yml` and `entry.yml`.

The image is published for `linux/amd64` only (checked 2026-10-31: no tag has an arm64 build), so both servers must be x86_64.

`xray_image_digest` pins `ghcr.io/xtls/xray-core` (the uplink containers and the exit; the multi-arch index digest). Pick a release tag and read its digest from the registry:

```bash
TAG=26.10.31
T=$(curl -s "https://ghcr.io/token?scope=repository:xtls/xray-core:pull" | jq -r .token)
curl -sI -H "Authorization: Bearer $T" -H "Accept: application/vnd.oci.image.index.v1+json" \
  https://ghcr.io/v2/xtls/xray-core/manifests/$TAG | grep -i docker-content-digest
# or: docker buildx imagetools inspect ghcr.io/xtls/xray-core:$TAG   (first "Digest:" line)
```

Put it into `vars.yml` and re-run `exit.yml` and `entry.yml` (`entry.yml` restarts `multihop-uplink-xray`, a short interruption in `reality` mode). The app-built `amnezia-xray` is separate: its Xray version comes from the vendored Dockerfile, not from this digest.

## Troubleshooting

On the entry:

```bash
docker exec amnezia-awg2 awg show               # users and handshakes
docker exec multihop-uplink awg show awg-uplink # uplink handshake and endpoint
ip rule show                                    # priorities 10100, 10110, 10120, 10130
ip -d link show <public iface> | grep group      # group 51820: rule 10120 ignores its routes (udev rule + re-resolve timer keep it; verify.yml checks it)
ip route show table multihop
iptables -S MULTIHOP-FWD
iptables -t mangle -S MULTIHOP-MARK
ipset list -t                                   # multihop_direct, multihop_force_exit (sizes)
journalctl -u 'multihop-*' --since '1 hour ago'
systemctl list-timers 'multihop-*'
cat /var/lib/multihop/backup/DRIFT              # present = app reinstalled the named containers
```

On the entry in `reality` mode (and with `entry_xray_enabled`):

```bash
docker logs --tail 50 multihop-uplink-xray      # uplink Xray: connection errors to the exit show here
ss -ltn | grep <uplink_tproxy_port>             # the TPROXY listener (127.0.0.1)
iptables -t mangle -S MULTIHOP-TPROXY           # TPROXY rules; absent in awg mode
ip route show table 51820                       # local default dev lo (reality) + blackhole backstop
ss -Htn state established dport = :<exit_reality_port>   # connections to the exit
docker logs --tail 50 amnezia-xray              # app Xray
ss -ltn | grep <entry_xray_port>
```

On the exit:

```bash
docker exec multihop-exit awg show awg-exit     # awg mode
docker logs --tail 50 multihop-exit-xray        # reality mode
ss -Htn state established sport = :<exit_reality_port>   # the entry's connections
journalctl -u 'multihop-*'
```

- No handshake on `awg-uplink`: check that `exit_domain` resolves to the exit, the exit's `exit_awg_port` is open (UDP), and `awg_*` parameters match (vault `vault_link_awg`).
- `reality` mode, users have no internet: `docker ps` shows `multihop-uplink-xray`? Is the TPROXY port listening and `MULTIHOP-TPROXY` present (see above)? `docker logs multihop-uplink-xray` and `multihop-exit-xray`: `exit_domain` resolution, `exit_reality_port` open, `vault_link_reality` and `reality_uuid` matching on both sides. Ping not working is expected.
- Users have no internet, uplink up: `verify.yml`; check `ip rule show` and `ip route show table multihop`.
- Users have no internet, uplink down: expected (fail-closed). Fix the uplink. While it is down the entry also drops the clients' AWG packets (the reverse-path filter finds no route back through the uplink), so the app shows no handshake at all.
- Run a backup now: `uv run ansible-playbook playbooks/backup.yml`.

## Development

```bash
make test    # pytest + bats
make lint    # shellcheck, ansible-lint, playbook syntax checks
```

Integration test on throwaway x86_64 Ubuntu hosts (root SSH; the hosts are wiped by their owner afterwards). Put the IPs in `tests/integration/.state/lab.env` (`ENTRY_IP`, `EXIT_IP`, `EXIT2_IP`, optional `CLIENT_IP`), the SSH key in `.state/id_ed25519` and the host keys in `.state/known_hosts`, and for the backup checks a real S3 bucket in `.state/s3.env` (`BACKUP_S3_ENDPOINT`, `BACKUP_S3_REGION`, `BACKUP_S3_BUCKET`, `BACKUP_S3_PREFIX`, `WRITER_ACCESS_KEY`, `WRITER_SECRET_KEY`, `READER_ACCESS_KEY`, `READER_SECRET_KEY`). Everything under `.state/` and the generated parts of `inventories/lab/` are gitignored.

```bash
tests/integration/run.sh init     # lab inventory + secrets (re-run after editing s3.env, and on fresh hosts)
tests/integration/run.sh deploy   # site.yml plus a test VPN client added like the app does
tests/integration/run.sh check    # PASS/FAIL per check; logs in .state/logs/
tests/integration/run.sh swap     # exit swap to EXIT2 (last)
tests/integration/run.sh clean    # optional: remove containers and state from the hosts
```

The lab runs in `reality` mode with `entry_xray_enabled`. Besides the AWG checks (`client_via_exit`, `client_fail_closed`, `drift`, `backup`, `swap_*`, ...) `check` covers: `reality_uplink`, `reality_throughput`, the fail-closed cases `fail_closed_reality_entry_xray`, `fail_closed_reality_exit_xray` and `fail_closed_reality_no_tproxy`, `icmp_blocked_reality`, `direct_and_force_exit_reality`, `xray_client_via_exit` (a stock Xray client added to `server.json` like the app does), `xray_restart_keeps_settings`, `xray_app_user_backup_valid` and `rollback_to_awg`. The app-adoption question above cannot be tested there (it needs the real app). `init` must be re-run on fresh hosts because the lab inventory and secrets (now including the Xray blocks) are generated there.
