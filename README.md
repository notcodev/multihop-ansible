# multihop-ansible

Ansible project that deploys a two-hop AmneziaWG VPN: an entry server managed from the Amnezia app, an AWG uplink to an exit server, split routing on the entry, encrypted S3 backups of the user state, and playbooks to swap either server.

## What this is

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

- Ansible builds the entry exactly like the app would (container `amnezia-awg2`, network `amnezia-dns-net`), so the app adopts it. Users are then managed in the app. Ansible never writes `clientsTable`.
- The entry's user state is a host bind mount (`/var/lib/multihop/entry-awg`) and is backed up (age-encrypted, change-only) to S3.
- Traffic from users goes through the exit. Destinations on the split-routing direct list (default: country `ru` plus your own lists) leave straight from the entry.
- Fail-closed: if the exit or the uplink is down, users lose internet; nothing leaks out of the entry's public IP (except the direct split list, by design).
- Re-running playbooks is safe: users added in the app are kept.

Ansible-owned things never match `grep amnezia` except `amnezia-awg2` and `amnezia-dns-net`: own containers are `multihop-uplink` / `multihop-exit`, host state is under `/var/lib/multihop/`.

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

   In `hosts.yml` set `ansible_user` (a user with sudo) and your SSH key setup (`ansible_ssh_private_key_file` or an agent), and `ansible_port` / `ssh_port` if SSH is not on 22 (`ssh_port` also opens it in the host firewall). Set `entry_domain`, `exit_domain`, ports, `backup_*` (except `backup_age_recipient`, which comes after step 3), and `awg_base_image_digest` (see "Updating the pinned image"). Point `inventory` in `ansible.cfg` at it or pass `-i inventories/prod`.

2. Vault password: put it in `.vault-pass` (gitignored; `ansible.cfg` reads it) or set `ANSIBLE_VAULT_PASSWORD_FILE`.

3. Generate the secrets, fill in the S3 and age fields, encrypt:

   ```bash
   uv run scripts/gen-secrets.py all > inventories/prod/group_vars/all/vault.yml
   uv run scripts/gen-secrets.py uplink-key > inventories/prod/group_vars/all/vault_uplink.yml
   mkdir -p ~/.config/multihop && age-keygen -o ~/.config/multihop/age.key   # prints the public key; keep the key out of the repo
   $EDITOR inventories/prod/group_vars/all/vault.yml
   uv run ansible-vault encrypt inventories/prod/group_vars/all/vault.yml inventories/prod/group_vars/all/vault_uplink.yml
   ```

   In `vault.yml` replace the `CHANGE_ME` values: `vault_backup_writer`, `vault_backup_reader`, and `vault_backup_age_identity` (the `AGE-SECRET-KEY-...` line from `~/.config/multihop/age.key`). Only now put the age **public** key (printed by `age-keygen`) in `vars.yml` as `backup_age_recipient`. The first line of the generated file suggests random ports for `entry_awg_port` / `exit_awg_port`. Each link gets its own random AmneziaWG 3.1 obfuscation values (Jc/Jmin/Jmax, S1–S4, non-overlapping H1–H4 ranges, a DNS-query I1) instead of the app's shared defaults; existing vaults keep their values. See `inventories/example/group_vars/all/vault.yml.example` for the structure (fake values). `vault_uplink.yml` holds `vault_uplink_entry` and is kept separate because swap-entry rotates it.

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

The fail-closed test stops `multihop-uplink` and checks that `amnezia-awg2` cannot reach the internet. It interrupts users for about a minute. Optional: `-e verify_ip_echo_url=...` (default `https://api.ipify.org`).

## Adding the server in the Amnezia app

Add the server by **domain** (`entry_domain`) with an SSH user that has sudo. The app detects AmneziaWG as already installed (expected to show "version 3.1": the Amnezia client labels a server that way when its `awg0.conf` carries the 3.1 options such as `HeaderProtectionKey` and `RekeyAfterTime`, which this setup writes; see `hasAwg3Markers` in amnezia-client `awgProtocolConfig.cpp`; expected behaviour, not a guarantee). Then add users and share keys as usual.

## Rules for the entry

- The entry runs only `amnezia-awg2` and `multihop-uplink`. Do not add other containers to its Docker bridges: the fail-closed exception for the AWG server's replies assumes `amnezia-awg2` is the only UDP sender on `docker0`/`amn0`.
- **Do not use the app's "remove / reinstall protocol", and do not edit AmneziaWG settings in the app.** The app reinstalls the container: new server keys, an empty user list, and our bind mount and the fixed NAT port range are gone. Every issued key stops working.
- Reinstalling also removes the container's fixed NAT port range, the basis of the AWG UDP reply exception, so user UDP from source port `entry_awg_port` could then leave via the entry's own IP.
- Drift detection: the backup timer checks every run that `amnezia-awg2` still has the bind mount, and with `entry_xray_enabled` that `amnezia-xray` still bind-mounts `/var/lib/multihop/entry-xray` (the app's reinstall puts its named volume there instead). If not, `multihop-backup` writes `/var/lib/multihop/backup/DRIFT` (one line per drifted container), still backs up the host state directories (they hold the last good state, and drift on one protocol must not stop the other's backup), and exits with code 2; `entry.yml` fails with recovery instructions. Look for it with `systemctl status multihop-backup.service` and `journalctl -u multihop-backup`.

## Operator constraints

- `entry.yml` needs a working exit: the `amnezia-awg2` image build (and any traffic from the entry's containers) goes through the uplink.
- `entry_awg_port` and `entry_awg_subnet` cannot change after the first deploy: `awg0.conf` is written only when absent, and a restore refuses a backup with another port or subnet. The same holds for `entry_xray_port`: `entry.yml` refuses to run when the entry's `server.json` has another port, and a restore refuses an `xray/server.json` with another port.
- Docker on the entry does not start if the routing and firewall rules cannot be applied (`ExecStartPre=multihop-entry-net up`): fail-closed rather than forwarding through the entry's IP. Check `systemctl status docker` and `journalctl -u docker` if it stays down; after fixing the cause run `systemctl reset-failed docker docker.socket && systemctl start docker` (systemd stops retrying after a few failed starts).
- Traffic from the entry's containers may leave only through the uplink, the public interface (direct split list and the AWG server's own UDP), or another Docker bridge. Anything to other NICs (e.g. a provider private network) is dropped. The exit also drops user traffic to private, CGNAT and link-local ranges (provider metadata).
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

With `entry_xray_enabled` the backup also holds the Xray state under `xray/` (`server.json`, `clientsTable` and the four `xray_*.key` files), and `restore.yml` restores it too. A backup without `xray/` (older, or made before Xray was enabled) restores only the AWG state and leaves the Xray state as it is, or seeds it from `vault_entry_xray` if there is none. A backup with `xray/` restored while Xray is disabled skips it with a notice.

Validation refuses any archive member that is not a regular file directly at the archive root or directly in `xray/` under one of those six names, and any `awg0.conf` key outside the AmneziaWG allow-list (no `PreUp`/`PostUp`/`PreDown`/`PostDown`, `SaveConfig`, `Table`, `DNS`; awg-quick would run hooks as root). It also requires `ListenPort` = `entry_awg_port` and `Address` inside `entry_awg_subnet`. `xray/server.json` must have exactly the app's shape: `log` with only a log level, one VLESS + REALITY inbound on `entry_xray_port`, and only a plain `freedom` outbound (no `routing`, `api`, `stats` or other sections, no other inbounds or outbounds); the key files must be single-line values of the right form. age does not prove who wrote a backup, and the entry's writer key can upload one, so if the old entry may have been compromised, restore a `backup_object` from before the compromise instead of `latest`. After a reinstall, the app may have to be re-pointed at the server (same domain, nothing else changes).

## Swap the exit

The exit's identity is entirely in the vault, so a new exit is identical and the entry needs no change.

1. In the inventory put the **new** host in `exit` (`ansible_host` = its public IPv4); optionally the old one in `exit_old`.
2. Run:

   ```bash
   uv run ansible-playbook playbooks/swap-exit.yml                 # leaves the old exit running
   uv run ansible-playbook playbooks/swap-exit.yml -e stop_old=yes # also stops the old exit
   ```

It deploys the exit, updates the DNS record for `exit_domain` (manual backend: it asks you to change the record and waits until resolvers return the new IP), waits for the entry's re-resolve timer (about 1 minute plus TTL) to flip the endpoint, forces a handshake, verifies, and stops the old exit when `stop_old=yes`.

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

## Updating the pinned image

The base image `amneziavpn/amneziawg-go` is pinned by digest in `awg_base_image_digest`:

```bash
curl -s https://hub.docker.com/v2/repositories/amneziavpn/amneziawg-go/tags/latest | jq -r .digest
```

Put the `sha256:...` value into `vars.yml` and re-run `exit.yml` and `entry.yml`.

The image is published for `linux/amd64` only (checked 2026-10-31: no tag has an arm64 build), so both servers must be x86_64.

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

On the exit:

```bash
docker exec multihop-exit awg show awg-exit
journalctl -u 'multihop-*'
```

- No handshake on `awg-uplink`: check that `exit_domain` resolves to the exit, the exit's `exit_awg_port` is open (UDP), and `awg_*` parameters match (vault `vault_link_awg`).
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
tests/integration/run.sh init     # lab inventory + secrets (re-run after editing s3.env)
tests/integration/run.sh deploy   # site.yml plus a test VPN client added like the app does
tests/integration/run.sh check    # PASS/FAIL per check; logs in .state/logs/
tests/integration/run.sh swap     # exit swap to EXIT2 (last)
tests/integration/run.sh clean    # optional: remove containers and state from the hosts
```
