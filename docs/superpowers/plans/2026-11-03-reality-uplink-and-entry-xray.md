# Reality Uplink and Entry Xray Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the entry ↔ exit AWG link with an Xray-only VLESS + REALITY transport over TCP with BBR (behind a flag), and add an optional, app-managed Amnezia Xray protocol for users on the entry.

**Architecture:**
- **Part 1, uplink (`uplink_transport: reality`):** bridge traffic from the app containers that is not a reply, direct-listed or local is TPROXY'd on the entry into `multihop-uplink-xray`. Its only outbound is VLESS + REALITY to `multihop-exit-xray`, which sends it to the internet through `freedom`, with private ranges blocked. The AWG uplink container is removed in this mode. `awg` mode is today's behaviour, unchanged.
- **Part 2, users:** `amnezia-xray` is built from the Amnezia 5.1.0.6 sources, with its state on a host bind mount. It sits on the same bridges, so its users' traffic takes the same path. A narrow conntrack exception covers its replies.

**Tech Stack:** Ansible (ansible-core ≥ 2.21, community.docker, ansible.posix), bash scripts tested with bats, Python filter plugins tested with pytest, Xray-core (`ghcr.io/xtls/xray-core`), iptables TPROXY/ipset/iproute2, systemd.

**Spec:**
- `docs/superpowers/specs/2026-11-03-reality-uplink-and-entry-xray-design.md`
- **`docs/superpowers/specs/2026-11-03-xray-only-uplink-addendum.md`**. The gate selected Xray-only; the addendum replaces design sections 7.1–7.4.
- Both build on `docs/superpowers/specs/2026-10-31-multihop-awg-design.md`.

Read all three before starting.

## Global Constraints

- The gate (Task 1) is done: the result is **Xray-only**. Wherever the design and the addendum differ, the addendum wins.
- **Target app** is Amnezia **5.1.0.6** (`amnezia-vpn/amnezia-client` tag `5.1.0.6`, commit `ac175c8`). Vendor the Xray `Dockerfile` and `start.sh` from `ac175c8`. The app source tarball is at `/private/tmp/claude-501/-Users-notcodev-Programming-PersonalProjects-multihop-ansible/d4a9d5dd-9b80-4187-b8da-e4d2052edc46/scratchpad/amnezia-src/` (commit `7f9b7db`). Re-download `ac175c8` for the two files that differ (`gh api repos/amnezia-vpn/amnezia-client/tarball/ac175c8`).
- **Role defaults:**

  | Variable | Default |
  |---|---|
  | `uplink_transport` | `awg` |
  | `exit_reality_port` | `443` |
  | `uplink_reality_site` | `dl.google.com` |
  | `uplink_tproxy_port` | `12345` |
  | `entry_xray_enabled` | `false` |
  | `entry_xray_port` | `443` |
  | `entry_xray_site` | `www.googletagmanager.com` |
  | `entry_xray_state_dir` | `/var/lib/multihop/entry-xray` |

  The prod inventory sets `uplink_transport: reality` and `entry_xray_enabled: true`.
- **Container names:** `multihop-exit-xray`, `multihop-uplink-xray`, `amnezia-xray`. In `reality` mode `multihop-uplink` (AWG) is absent on the entry, while `multihop-exit` (AWG) keeps running on the exit.
- **Secrets:**

  | Where | Contents |
  |---|---|
  | `vault_link_reality` | `{private_key, public_key, short_id}`, the exit's REALITY identity |
  | `vault_uplink_entry.reality_uuid` | the entry's VLESS id, in `vault_uplink.yml`; rotated with the AWG uplink key |
  | `vault_entry_xray` | `{uuid, private_key, public_key, short_id}` |

  REALITY keys are X25519 encoded as **base64url without padding** (43 chars). `short_id` is 16 lowercase hex chars. UUIDs are uuid4 strings.
- **Xray image:** `ghcr.io/xtls/xray-core`, pinned by digest in `xray_image_digest` and tagged locally as `multihop/xray:pinned`. It must be release `26.10.31` or later. Run it with `user: "0:0"`.
- **The entry Xray has exactly one outbound,** VLESS + REALITY to the exit: no `freedom`, no other outbound (addendum 3.3).
- **The exit Xray `freedom` blocks**, via `finalRules` in this order: `169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, <exit ansible_host>/32`, then allows everything else.
- **BBR:** `net.core.default_qdisc=fq` and `net.ipv4.tcp_congestion_control=bbr` on both servers, persistent, in both transport modes.
- **Ansible never rewrites app-owned files after first deploy:** `server.json`, `clientsTable`, `xray_*.key`, `awg0.conf`, `wireguard_*.key`.
- **Fail-closed holds in every mode** (addendum 3.3). Nothing from the bridges may leave via the entry's IP except:
  - the direct split list;
  - AWG server UDP from `entry_awg_port`;
  - the REPLY direction of connections DNAT'ed to `entry_xray_port`.
- **Never run on prod without the owner's go-ahead for that step:** prod is `entry1` 147.45.212.14 and `exit2` 213.182.213.237, with inventory `inventories/prod`. The lab is `tests/integration/run.sh`.
- Use the existing test entry points: `make test` (pytest + bats) and `make lint` (shellcheck, ansible-lint, syntax checks). Both must pass at the end of every task.

## Review Focus

1. **Existing vaults lack the new blocks.** Running `entry.yml`/`exit.yml` with `uplink_transport: reality` or `entry_xray_enabled: true` on a vault without `vault_link_reality`, `vault_uplink_entry.reality_uuid` or `vault_entry_xray` must fail early with a message that names the `gen-secrets.py` subcommand to run, not with a Jinja undefined error. Tests: Tasks 4 and 8.
2. **Rollback from `reality` to `awg`.** Re-running with `uplink_transport: awg` must:
   - remove the `local` route from table 51820 and `MULTIHOP-TPROXY`;
   - restore `multihop-uplink` and its `default dev awg-uplink` route;
   - remove `multihop-uplink-xray`;
   - keep `multihop-reresolve` behaving as before.

   Tests: Task 5 bats (mode switch both ways) and a lab check in Task 10.
3. **Restoring an old backup that has no `xray/` directory** with `entry_xray_enabled: true` must restore AWG and seed Xray from the vault. A backup with `xray/` while Xray is disabled must restore AWG and skip Xray with a notice. Tests: Task 9.
4. **Port collisions.** `entry_xray_port` equal to `ssh_port`, any `extra_input_tcp_ports` entry, or `uplink_tproxy_port` must be refused before anything changes. Test: Task 8.
5. **The app restarts `amnezia-xray`** (`docker restart`, as it does on every user change). Afterwards the bind mount, the ephemeral port range that excludes `entry_awg_port`, and BBR must still be in effect. Test: Task 10 lab check.

---

### Task 1 (DONE — result: Xray-only, see addendum section 1): Gate on prod — AWG-over-REALITY vs Xray-only (operational, no repo changes)

**Files:** none committed. Scripts live in the scratchpad.

**Interfaces:**
- Consumes: SSH as root with `~/.ssh/multihop-vpn` to 147.45.212.14 (entry) and 213.182.213.237 (exit). Spike scripts as reference: `.../scratchpad/reality-spike.sh`, `spike-up.sh`, `spike-down.sh`.
- Produces: a numbers table and the decision (`awg-over-reality` or `xray-only`), reported to the owner.

- [ ] **Step 1: Get the owner's go-ahead for a throwaway test on prod.** The real uplink and users are not touched.
- [ ] **Step 2: Bring up the test pair.**
  - Xray containers `gate-xray` on both hosts, host network, `ghcr.io/xtls/xray-core:latest`, `--user 0:0`.
    - Exit: VLESS + REALITY on tcp/8443, `target` and `serverNames` `dl.google.com`, `freedom` with `redirect: "127.0.0.1:51899"` and `finalRules` allowing only udp 127.0.0.1:51899.
    - Entry: `tunnel` inbound on udp 127.0.0.1:10899 → VLESS outbound to 213.182.213.237:8443, plus a second `tunnel` inbound on tcp 127.0.0.1:15201 for the Xray-only baseline.
  - A temporary AWG pair `gate-awg` on subnet 172.16.250.0/30: `amneziawg-go` in a container using the pinned `multihop/awg-base:pinned` image, MTU 1280, plain WireGuard params (no obfuscation needed inside the tunnel). Exit side listens on 51899; entry side has `Endpoint = 127.0.0.1:10899`.
  - Temporary `MULTIHOP-IN` rule on the exit: tcp 8443 from the entry IP.
  - BBR on both hosts.
- [ ] **Step 3: Measure.** `iperf3 -s -B 172.16.250.1` on the exit, then on the entry:
  - `iperf3 -c 172.16.250.1 -P 4 -R -t 60`
  - `iperf3 -c 172.16.250.1 -P 1 -R -t 60`
  - `iperf3 -c 172.16.250.1 -u -b 100M -l 1200 -R -t 30`

  Keep the per-second lines.
- [ ] **Step 4: Measure the Xray-only baseline in the same session.** `iperf3 -s -B 213.182.213.237` on the exit, then `iperf3 -c 127.0.0.1 -p 15201 -P 4 -R -t 60` and `-P 1` on the entry.
- [ ] **Step 5: Clean up.** Remove both `gate-*` containers and the config dirs, kill iperf3, delete the temporary firewall rule, and restore `cubic`/`fq_codel`. Expected: `docker ps -a` shows no `gate-*`, `iptables -S MULTIHOP-IN` shows no 8443 rule, and `docker exec multihop-uplink awg show awg-uplink latest-handshakes` shows a handshake under 180 s old.
- [ ] **Step 6: Decide (spec 7.0).**
  - **`awg-over-reality`** if all of these hold for the 4-stream AWG run:
    - SUM ≥ 150 Mbit/s;
    - SUM ≥ 0.75 × the 4-stream Xray-only SUM;
    - no per-second interval at 0.00 bits/sec.
  - **`xray-only`** otherwise.
- [ ] **Step 7: Report.** Give the owner the table and the decision. On `xray-only`, stop here and write the spec 7.6 addendum for approval.

### Task 2: REALITY/Xray secrets and vault structure

**Files:**
- Create: `plugins/filter/xray.py`
- Modify: `scripts/gen-secrets.py`
- Modify: `inventories/example/group_vars/all/vault.yml.example` (also the `vault_uplink.yml` example comment)
- Modify: `tests/render/fixture_vars.yml` (add `vault_link_reality`, `vault_entry_xray` and `vault_uplink_entry.reality_uuid` with fixed fake values)
- Test: `tests/test_xray_filter.py` (create), `tests/test_gen_secrets.py`

**Interfaces:**
- Produces, in `plugins/filter/xray.py`:
  - `reality_genkey() -> str`: X25519 private key, base64url without padding.
  - `reality_pubkey(priv: str) -> str`
  - `gen_short_id(rng) -> str`: 16 lowercase hex chars.
  - `gen_uuid() -> str`: uuid4.
  - `xray_port_range(awg_port: int) -> str`: `"1024 <awg_port-1>"` when `awg_port - 1 - 1024 >= 10000`, else `"<awg_port+1> 65535"`. Same rule as `roles/entry_app/templates/start.sh.j2`.
  - `FilterModule` exposing `xray_port_range`.
- Produces, in `scripts/gen-secrets.py`:
  - `xray` prints a YAML document with exactly `vault_link_reality` (`private_key`, `public_key`, `short_id`) and `vault_entry_xray` (`uuid`, `private_key`, `public_key`, `short_id`).
  - `uplink-key` prints `vault_uplink_entry` with `private_key`, `public_key` **and `reality_uuid`**.
  - `all` includes `vault_link_reality` and `vault_entry_xray`.

- [ ] **Step 1: Write the failing tests** in `tests/test_xray_filter.py`:
  - `test_reality_key_roundtrip`: decode `reality_genkey()` with `base64.urlsafe_b64decode(k + "=")` to exactly 32 bytes. The key is 43 chars with no `=`, `+` or `/`. `reality_pubkey` gives the same result as the `cryptography` X25519 public key encoded the same way.
  - `test_reality_pubkey_known_vector`: a fixed private key maps to a fixed public key. Generate the vector once with `docker run --rm ghcr.io/xtls/xray-core:latest x25519 -i <priv>` (on any host with docker; ask the controller if none is available) and hardcode both values.
  - `test_short_id_hex16`: matches `^[0-9a-f]{16}$`.
  - `test_xray_port_range`: `xray_port_range(51820) == "1024 51819"` and `xray_port_range(5000) == "5001 65535"`.

  In `tests/test_gen_secrets.py`:
  - `test_xray_subcommand_doc`: the keys are exactly `{"vault_link_reality", "vault_entry_xray"}`, with the key sets listed above; each `public_key == reality_pubkey(private_key)`; no value is shared between blocks.
  - `test_uplink_key_doc` also asserts that `reality_uuid` is a valid uuid4.
  - `test_all_outputs_valid_vault_doc` also asserts both new blocks.
- [ ] **Step 2: Run** `uv run pytest tests/test_xray_filter.py tests/test_gen_secrets.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** `plugins/filter/xray.py`, reusing the X25519 primitives already imported in `awg.py`. Then extend `scripts/gen-secrets.py` and update its usage docstring.
- [ ] **Step 4: Update the examples.**
  - Add both blocks with obviously fake values to `vault.yml.example`, with comments:
    - `vault_link_reality` is the exit's REALITY identity; the exit is rebuilt from it.
    - `vault_entry_xray` seeds the first deploy only.
  - Mention `reality_uuid` in the `vault_uplink.yml` comment there.
  - Add all three to `tests/render/fixture_vars.yml`.
- [ ] **Step 5: Run** `uv run pytest tests -q`. Expected: all pass.
- [ ] **Step 6: Commit** with `git commit -m "feat: generate REALITY and entry Xray secrets"`.

### Task 3: BBR and the pinned Xray image in the common role

**Files:**
- Modify: `roles/common/tasks/main.yml`, `roles/common/defaults/main.yml`, `roles/common/templates/multihop.env.j2`
- Create: `roles/common/tasks/xray-image.yml`
- Modify: `inventories/example/group_vars/all/vars.yml` (add `xray_image_digest` with a real digest)
- Test: `tests/test_playbooks.py` (add a test), `tests/test_render.py`

**Interfaces:**
- Produces:
  - Local image tag `multihop/xray:pinned`, present when `uplink_transport == 'reality'`. The include runs on both entry and exit. `amnezia-xray` does not use it: that image is built from the app's Dockerfile (Task 8).
  - Marker file `/var/lib/multihop/xray.digest`.
  - Defaults `common_xray_image: ghcr.io/xtls/xray-core`, `common_xray_image_tag: multihop/xray:pinned`, `common_input_tcp_ports: []`.
  - `INPUT_TCP_PORTS` in `multihop.env` = `common_input_tcp_ports + extra_input_tcp_ports`.

- [ ] **Step 1: Write the failing tests.**
  - `test_common_sets_bbr` (in `tests/test_playbooks.py`, parsing `roles/common/tasks/main.yml` with yaml): the sysctl loop contains `{key: net.core.default_qdisc, value: fq}` and `{key: net.ipv4.tcp_congestion_control, value: bbr}`, and a task writes `tcp_bbr` to `/etc/modules-load.d/multihop-bbr.conf`.
  - `test_input_tcp_ports_combines_common_and_extra` (in `tests/test_render.py`): rendering `multihop.env.j2` with `common_input_tcp_ports: [443]` and `extra_input_tcp_ports: [8080]` gives `INPUT_TCP_PORTS="443 8080"`.
- [ ] **Step 2: Run both tests.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - Load `tcp_bbr` before the sysctl task: `community.general.modprobe` if that collection is in `requirements.yml`, otherwise a `command: modprobe tcp_bbr` with `changed_when: false`. Persist it in `/etc/modules-load.d/multihop-bbr.conf`.
  - Add the two sysctls to the existing loop.
  - `xray-image.yml` mirrors the existing awg-base pull/tag/untag/marker block, using `common_xray_image@xray_image_digest`.
  - Get the digest of the chosen release with `docker buildx imagetools inspect ghcr.io/xtls/xray-core:<tag>` (or `crane digest`) and record the tag in a comment next to `xray_image_digest`.
- [ ] **Step 4: Run** `make test lint`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -m "feat: BBR on both servers and pinned Xray image"`.

### Task 4: Exit — REALITY server `multihop-exit-xray`

**Files:**
- Create: `roles/exit/templates/xray-exit.json.j2`, `roles/common/tasks/assert-vault.yml`, `tests/render/assert_vault.yml`
- Modify: `roles/exit/tasks/main.yml`, `roles/exit/defaults/main.yml`, `roles/exit/handlers/main.yml`, `playbooks/exit.yml`
- Test: `tests/test_render.py`, `tests/test_playbooks.py`

**Interfaces:**
- Consumes: `vault_link_reality` and `vault_uplink_entry.reality_uuid` (Task 2); `multihop/xray:pinned` and `common_input_tcp_ports` (Task 3).
- Produces:
  - `roles/common/tasks/assert-vault.yml`, with inputs:
    - `assert_vault_var`: a variable name;
    - `assert_vault_keys`: a list of required keys;
    - `assert_vault_hint`: the gen-secrets command to name.

    It asserts the variable is defined, is a mapping, and has non-empty values for all keys. Otherwise it fails with `fail_msg` "<var> is missing <keys>: run `<hint>` and add the output to the vault".
  - Container `multihop-exit-xray`: host network, `restart_policy: always`, `user: "0:0"`, config `{{ exit_state_dir }}/xray-exit.json` mounted read-only at `/etc/xray/config.json`, command `run -c /etc/xray/config.json`.
  - Handler `Restart multihop-exit-xray`.
  - In `uplink_transport: awg` mode, `multihop-exit-xray` is `absent`. In both modes `multihop-exit` (AWG) runs as today.

- [ ] **Step 1: Write the failing test `test_exit_xray_config`.** Render with fixture vars plus `exit_reality_port: 443` and `ansible_host: 198.51.100.7`, then `json.loads` the result. Assert:
  - The single inbound has `port == 443`, `protocol == "vless"` and `settings.decryption == "none"`.
  - `settings.clients == [{"id": <fixture vault_uplink_entry.reality_uuid>, "flow": "xtls-rprx-vision"}]`.
  - `streamSettings.network == "raw"` and `security == "reality"`.
  - `realitySettings.target == "dl.google.com:443"`, `serverNames == ["dl.google.com"]`, `privateKey == <fixture>`, `shortIds == [<fixture short_id>]`.
  - `realitySettings.limitFallbackUpload` and `limitFallbackDownload` each have `afterBytes > 0` and `bytesPerSec > 0`.
  - The only outbound is `freedom`, with `settings.finalRules == [{"action": "block", "ip": ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "198.51.100.7/32"]}, {"action": "allow"}]`.
  - There is no `redirect`.
- [ ] **Step 2: Write the failing test `test_missing_reality_vault_message`** (in `tests/test_playbooks.py`). Run `ansible-playbook -i localhost, -e ansible_connection=local tests/render/assert_vault.yml -e '{"assert_vault_var": "vault_link_reality", "assert_vault_keys": ["private_key", "public_key", "short_id"], "assert_vault_hint": "uv run scripts/gen-secrets.py xray"}'`. Expect a non-zero rc and `gen-secrets.py xray` in the output. Re-run with a full `vault_link_reality` added; expect rc 0.
- [ ] **Step 3: Run** the tests. Expected: FAIL.
- [ ] **Step 4: Implement.**
  - The exit role starts, in `reality` mode, with two includes of `assert-vault.yml`:
    - `vault_link_reality` with the three keys and hint `uv run scripts/gen-secrets.py xray`;
    - `vault_uplink_entry` with `[reality_uuid]` and hint `uv run scripts/gen-secrets.py uplink-key > .../vault_uplink.yml` (it rotates the AWG uplink key too; deploy the exit, then the entry).
  - Write the template and tasks.
  - In `playbooks/exit.yml`, pass `common_input_tcp_ports: "{{ [exit_reality_port] if uplink_transport == 'reality' else [] }}"` to the common role.
  - Check the Xray 26 field names (`finalRules`, `limitFallback*`, `raw`) against context7 `/xtls/xray-docs-next` before writing.
- [ ] **Step 5: Run** `make test lint`. Expected: pass.
- [ ] **Step 6: Commit** with `git commit -m "feat: REALITY server on the exit"`.

### Task 5: Entry routing — TPROXY into Xray (reality mode) and the Xray reply exception (both modes)

**Files:**
- Modify: `roles/entry_uplink/files/multihop-entry-net`
- Modify: the `uplink` block in `roles/entry_uplink/tasks/main.yml`. Add:
  - `UPLINK_TRANSPORT`;
  - `UPLINK_TPROXY_PORT`;
  - `ENTRY_LOCAL_NETS`: the bridges' subnets, from `community.docker.docker_network_info` for `bridge` and `entry_app_network`, space-separated. The network is created earlier by `entry_app`; if it does not exist yet, use `entry_app_network_subnet`.
  - `ENTRY_XRAY_PORT`: empty unless `entry_xray_enabled`.
- Test: `tests/bats/entry_net.bats`

**Interfaces:**
- Consumes: the env keys above.
- Produces, exactly as in addendum section 3:
  - In `reality` mode, table 51820 has `local default dev lo` plus the existing blackhole.
  - `MULTIHOP-MARK` uses the addendum 3.2 layout in reality mode. In awg mode it keeps today's rules, plus the two conntrack reply rules whenever `ENTRY_XRAY_PORT` is set.
  - New chain `MULTIHOP-TPROXY`, in reality mode only.
  - `MULTIHOP-FWD` gains, whenever `ENTRY_XRAY_PORT` is set and per bridge before its DROP, for each of tcp and udp: `-i $br -o $PUBLIC_IFACE -p <proto> -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport $ENTRY_XRAY_PORT -j RETURN`.
  - `up` in awg mode removes any `local default` route from table 51820 and drops `MULTIHOP-TPROXY`. `down` removes both.

- [ ] **Step 1: Write the failing bats tests.** Extend the fake `ip` in the test setup to keep table-51820 routes by type if needed.
  - `reality: table 51820 has local default and blackhole`
  - `reality: MULTIHOP-MARK has the addendum layout in order`: assert the exact rule list, in order, for `ENTRY_AWG_PORT=51470`, `ENTRY_XRAY_PORT=443`, `UPLINK_TPROXY_PORT=12345`, `ENTRY_LOCAL_NETS="172.17.0.0/16 172.29.172.0/24"`.
  - `reality: MULTIHOP-TPROXY rules exact and installed before MULTIHOP-MARK references it`
  - `awg: no local route, no MULTIHOP-TPROXY, MULTIHOP-MARK as today plus xray reply rules when ENTRY_XRAY_PORT set`
  - `switch reality -> awg removes local route and MULTIHOP-TPROXY`
  - `switch awg -> reality adds them`
  - `xray reply exception in MULTIHOP-FWD before the bridge DROP lines; absent when ENTRY_XRAY_PORT empty`
  - `no rule anywhere matches --sport 443`
  - The existing `IPT_GUARD` backstop check reports no violations in all of the above.
- [ ] **Step 2: Run** `bats tests/bats/entry_net.bats`. Expected: new tests FAIL, existing tests pass.
- [ ] **Step 3: Implement** in `multihop-entry-net`.
  - Keep the ordering guarantees in its header: the backstop and blackhole come before any rule, and chains are swapped atomically.
  - Update the header comment with the reality-mode paths and the fail-closed argument (addendum 3.3, in brief).
  - Add `ENTRY_XRAY_PORT`, `UPLINK_TRANSPORT`, `UPLINK_TPROXY_PORT` and `ENTRY_LOCAL_NETS` to the role's env block.
- [ ] **Step 4: Run** `make test lint`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -m "feat: TPROXY uplink routing and Xray reply exception on the entry"`.

### Task 6: Entry — `multihop-uplink-xray` container, mode switch and re-resolve

**Files:**
- Create: `roles/entry_uplink/templates/xray-uplink.json.j2`
- Modify: `roles/entry_uplink/tasks/main.yml`, `roles/entry_uplink/defaults/main.yml`, `roles/entry_uplink/handlers/main.yml`, `roles/entry_uplink/files/multihop-reresolve`
- Test: `tests/test_render.py`, `tests/bats/reresolve.bats`

**Interfaces:**
- Consumes: `vault_link_reality`, `vault_uplink_entry.reality_uuid` (Task 2); the image (Task 3); `assert-vault.yml` (Task 4); the env keys (Task 5).
- Produces:
  - **Reality mode:**
    - `multihop-uplink-xray` runs: host network, `user: "0:0"`, `capabilities: [NET_ADMIN]`, `restart_policy: always`.
    - `multihop-uplink` (AWG) is `absent`.
    - Order: `multihop-net` first (already the case), then the container.
  - **AWG mode:** the reverse, with `multihop-uplink` exactly as today.
  - Env key `UPLINK_STATE_DIR`.
  - State file `{{ entry_uplink_state_dir }}/exit-ip`, written by `multihop-reresolve`.

- [ ] **Step 1: Write the failing render test `test_uplink_xray_config`.** `json.loads` the rendered `xray-uplink.json.j2` and assert:
  - **Exactly one inbound:**
    - `listen == "127.0.0.1"`, `port == 12345`, `protocol == "tunnel"`;
    - `settings.network == "tcp,udp"` and `settings.followRedirect is True`;
    - `streamSettings.sockopt.tproxy == "tproxy"`;
    - no `sniffing`, or `sniffing.enabled is False`.
  - **Exactly one outbound:**
    - `protocol == "vless"` to `address == <exit_domain>` and `port == 443`;
    - user `id == <fixture reality_uuid>`, `flow == "xtls-rprx-vision"`, `encryption == "none"`;
    - stream `network == "raw"` and `security == "reality"`;
    - `realitySettings` exactly `{"serverName": "dl.google.com", "fingerprint": "chrome", "password": <vault_link_reality.public_key>, "shortId": <short_id>}`, with no `target` key.
  - **No `freedom` or `blackhole` outbound anywhere.**
  - `policy.levels."0".connIdle >= 300`.

  Check the tunnel/dokodemo transparent-proxy field names against context7 `/xtls/xray-docs-next` first. If a name differs, use the documented one and say so in the report.
- [ ] **Step 2: Write the failing bats tests** in `tests/bats/reresolve.bats`:
  - `reality mode restarts uplink xray when the exit IP changes`: `UPLINK_TRANSPORT=reality`, `getent` returns `203.0.113.9`, the `exit-ip` file holds `203.0.113.8`. Expect `docker restart multihop-uplink-xray`, no `awg` call, and the file now holds `203.0.113.9`.
  - `reality mode first run records the IP without a restart`: the file is absent; it is written and docker is not called.
  - `reality mode does nothing when the IP is unchanged`
  - `reality mode keeps everything on a failed resolve`
  - The existing AWG-mode tests still pass.
- [ ] **Step 3: Run** `uv run pytest tests/test_render.py -k uplink -v` and `bats tests/bats/reresolve.bats`. Expected: new tests FAIL.
- [ ] **Step 4: Implement the template, the mode-dependent container tasks and the reresolve branch.**
  - In reality mode, start with the two `assert-vault.yml` includes from Task 4.
  - `awg-uplink.conf` is still rendered in reality mode (cheap, and keeps the rollback a one-variable change), but no container uses it.
- [ ] **Step 5: Run** `make test lint`. Expected: pass.
- [ ] **Step 6: Commit** with `git commit -m "feat: Xray uplink container on the entry"`.

### Task 7: Swap and verify playbooks for both transports; fix the old-exit tug-of-war (awg mode)

**Files:**
- Modify: `playbooks/swap-exit.yml`, `playbooks/verify.yml`, `playbooks/tasks/verify-entry.yml`
- Test: `tests/test_playbooks.py`

**Interfaces:**
- Consumes: container names and `uplink_transport` (Tasks 4–6).
- Produces, in `swap-exit.yml` after the DNS play:
  1. On the entry: `resolvectl flush-caches` (ignore a missing resolvectl).
  2. **Reality mode:**
     - `docker restart multihop-uplink-xray`;
     - generate traffic: a curl to the IP echo URL from inside `amnezia-awg2`, as `verify-entry.yml` does;
     - wait up to 5 min until `ss -Htn state established dst <new exit ip> dport = :<exit_reality_port>` on the entry is non-empty;
     - no AWG handshake waits.
  3. **AWG mode:**
     - **if `exit_old` has a host, stop `multihop-exit` on it before the handshake waits**; keep its restart policy unless `stop_old=yes`, which also sets `restart_policy: "no"` as today;
     - then the existing endpoint and handshake waits.
- Produces, in `verify-entry.yml`:
  - **Reality mode:**
    - `multihop-uplink-xray` is running and `ss -Hltn sport = :<uplink_tproxy_port>` on the entry is non-empty;
    - the egress IP from `amnezia-awg2` (and `amnezia-xray` when enabled) is the exit's IPv4;
    - on the exit, an established TCP connection from the entry's IPv4 to `exit_reality_port` exists. This takes the place of the awg-exit byte-counter checks.
  - **AWG mode:** unchanged.
- Produces, in `verify.yml`: the fail-closed block stops `multihop-uplink-xray` in reality mode (`multihop-uplink` in awg mode) and restarts it in `always`.

- [ ] **Step 1: Write the failing tests** in `tests/test_playbooks.py`, parsing the YAML structure as the existing tests there do:
  - `test_swap_exit_flushes_entry_resolver`: a task on the entry runs `resolvectl flush-caches`, after the DNS update play.
  - `test_swap_exit_awg_stops_old_before_handshake_wait`: in awg mode, the stop-old-exit task comes before the first `wait-handshake.yml` include.
  - `test_swap_exit_reality_restarts_uplink_xray_and_waits_for_connection`
  - `test_verify_fail_closed_stops_uplink_xray_in_reality_mode`
- [ ] **Step 2: Run** the tests. Expected: FAIL.
- [ ] **Step 3: Implement.** `swap-entry.yml` needs no change: the UUID rotates through `gen-secrets.py uplink-key` (Task 2).
- [ ] **Step 4: Run** `make test lint`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -m "feat: swap and verify for the Xray uplink; fix exit swap with the old exit running"`.

### Task 8: Role `entry_xray` — app-compatible `amnezia-xray`

**Files:**
- Create:
  - `roles/entry_xray/defaults/main.yml`
  - `roles/entry_xray/tasks/main.yml`
  - `roles/entry_xray/tasks/restore.yml`
  - `roles/entry_xray/files/Dockerfile` (vendored from `ac175c8`, with a header comment naming the commit and the changes)
  - `roles/entry_xray/templates/start.sh.j2` (vendored `start.sh` with `$XRAY_SERVER_PORT` substituted)
  - `roles/entry_xray/templates/server.json.j2`
- Modify: `playbooks/entry.yml` (add the role after `entry_app`, when `entry_xray_enabled`)
- Test: `tests/test_render.py`, `tests/test_playbooks.py`

**Interfaces:**
- Consumes: `vault_entry_xray` and `xray_port_range` (Task 2).
- Produces:
  - **Container `amnezia-xray`**, configured like `client/server_scripts/xray/run_container.sh`:
    - `privileged`, capability `NET_ADMIN`, `restart_policy: always`, `log_driver: none`;
    - published `entry_xray_port` on tcp **and** udp;
    - networks: `bridge` then `entry_app_network`;
    - bind mount `{{ entry_xray_state_dir }}:/opt/amnezia/xray`;
    - sysctls `net.ipv4.tcp_congestion_control: bbr` and `net.ipv4.ip_local_port_range: "{{ entry_awg_port | int | xray_port_range }}"`.
  - After start: `docker exec` creates `/dev/net/tun`, as `run_container.sh` does.
  - Build label `org.multihop.build`, as in `entry_app`.
  - Drift assert on the `/opt/amnezia/xray` mount, before and after, mirroring `entry_app`.
  - `restore.yml` consumes `entry_xray_restore_dir`: the controller-side path of the staged `xray/` directory from Task 9.

- [ ] **Step 1: Write the failing test `test_entry_xray_server_json`.** Render `server.json.j2` and compare `json.loads` **for equality** with the structure the app writes (`XrayServerConfig::toServerInboundJson` with default settings):

  ```json
  {"log": {"loglevel": "error"},
   "inbounds": [{"port": 443, "protocol": "vless",
     "settings": {"clients": [{"id": "<vault uuid>", "flow": "xtls-rprx-vision"}], "decryption": "none"},
     "streamSettings": <server streamSettings for defaults>}],
   "outbounds": [{"protocol": "freedom"}]}
  ```

  - Fill in `<server streamSettings for defaults>` from `XrayServerConfig::streamSettingsJson(XrayStreamSide::Server)` in `client/core/models/protocols/xrayProtocolConfig.cpp`, using defaults transport `raw`, security `reality`, flow `xtls-rprx-vision` and site `www.googletagmanager.com`.
  - `realitySettings` must be exactly `{"dest": "www.googletagmanager.com:443", "privateKey": <vault>, "serverNames": ["www.googletagmanager.com"], "shortIds": [<vault short_id>]}`.
  - Keep this expected JSON as `tests/fixtures/amnezia-xray-server.json`, with the fixture vault values.
- [ ] **Step 2: Write the failing test `test_entry_xray_start_sh`.** `start.sh.j2` rendered with `entry_xray_port: 443` equals the vendored `start.sh` with `$XRAY_SERVER_PORT` replaced by `443`, and nothing else differs.
- [ ] **Step 3: Write the failing test `test_entry_xray_port_collision_refused`.** Put the port checks in `roles/entry_xray/tasks/checks.yml`, which also includes `roles/common/tasks/assert-vault.yml` (Task 4 interface) with `assert_vault_var: vault_entry_xray`, `assert_vault_keys: [uuid, private_key, public_key, short_id]` and `assert_vault_hint: uv run scripts/gen-secrets.py xray`. Run them through a small play `tests/render/entry_xray_checks.yml`, the same way as Task 4's test. Each of these must give a non-zero rc with the offending variable named in the output:
  - `entry_xray_port` = `ssh_port`;
  - `entry_xray_port` in `extra_input_tcp_ports`;
  - `entry_xray_port` = `uplink_tproxy_port`;
  - a missing `vault_entry_xray`.

  The fixture values give rc 0.
- [ ] **Step 4: Run** the tests. Expected: FAIL.
- [ ] **Step 5: Implement the role, mirroring `roles/entry_app/tasks/main.yml` task by task.**
  - Seed when `server.json` is absent: `xray_uuid.key`, `xray_private.key`, `xray_public.key` and `xray_short_id.key`, each value followed by `\n`, then `server.json`.
  - No INPUT firewall rule is needed. Docker DNATs published ports, so they pass FORWARD and `DOCKER-USER`, not `MULTIHOP-IN`, just as `entry_awg_port` works today. `MULTIHOP-FWD` only restricts traffic coming *from* the bridges.
  - `restore.yml`: stop the container, replace the state dir contents with the staged `xray/` files, start it again.
- [ ] **Step 6: Run** `make test lint`. Expected: pass.
- [ ] **Step 7: Commit** with `git commit -m "feat: app-managed Amnezia Xray on the entry"`.

### Task 9: Backups and restore carry the Xray state

**Files:**
- Modify:
  - `roles/backup/files/multihop-backup`
  - `roles/backup/tasks/main.yml` (env: `ENTRY_XRAY_STATE_DIR`, empty when Xray is disabled)
  - `plugins/filter/backup.py`
  - `playbooks/tasks/fetch-backup.yml` (pass `entry_xray_port` to the validator)
  - `roles/entry_app/tasks/restore.yml` (ignore the `xray/` subdir when copying)
  - `playbooks/entry.yml` and `playbooks/restore.yml` (call `entry_xray` restore when `xray/` exists and Xray is enabled; otherwise print a notice)
- Test: `tests/test_backup_validate.py`, `tests/bats/backup.bats`, `tests/test_fetch_backup.py`

**Interfaces:**
- **Archive layout:** AWG files at the archive root, unchanged, so old backups stay valid. Xray files under `./xray/`: exactly the files present out of `server.json`, `clientsTable`, `xray_uuid.key`, `xray_private.key`, `xray_public.key`, `xray_short_id.key`. Built deterministically; the hash changes only when either state changes.
- **Drift:** a missing mount on `amnezia-awg2` or `amnezia-xray` writes `DRIFT` (one line per container). The backup still archives and uploads the **host** state directories, which hold the last good state, and then exits 2. This is a deliberate change from today, where AWG drift exited before archiving (spec 8.3: drift on one protocol must not stop the other's backup).
- **New function** `xray_server_json_problems(text: str, port: int) -> list[str]` in `backup.py`.
- `backup_archive_problems(path, port, subnet, xray_port=None)` accepts the `xray/` directory and the six names only, validated with the function above.

- [ ] **Step 1: Write the failing tests** in `tests/test_backup_validate.py`:
  - `test_xray_dir_accepted`: an archive with valid AWG root files plus `xray/server.json` (the Task 8 fixture) and the four key files has no problems.
  - `test_xray_unknown_file_rejected`: `xray/evil.sh` is reported.
  - `test_xray_nested_dir_rejected`: `xray/a/b` is reported.
  - `test_xray_server_json_extra_sections_rejected`: each of `routing`, `api`, `stats`, a second inbound, or a non-freedom outbound is reported.
  - `test_xray_server_json_wrong_port_rejected`: port 8443 with `xray_port=443` is reported.
  - `test_old_backup_without_xray_still_valid`: an existing fixture archive has no problems.
- [ ] **Step 2: Write the failing tests** in `tests/bats/backup.bats`:
  - `archive contains xray subdir when ENTRY_XRAY_STATE_DIR is set`
  - `xray drift writes DRIFT, still uploads, exits 2`
  - `awg drift writes DRIFT, still uploads host state, exits 2` (replaces the old "no upload on drift" expectation)
  - `hash unchanged when neither state changed`
- [ ] **Step 3: Run** `uv run pytest tests/test_backup_validate.py tests/test_fetch_backup.py -v` and `bats tests/bats/backup.bats`. Expected: new tests FAIL.
- [ ] **Step 4: Implement** the script, validator and restore wiring. The restore of an `xray/`-less backup with Xray enabled leaves seeding to `entry_xray` (Review Focus 3); add a `test_fetch_backup.py` case for it.
- [ ] **Step 5: Run** `make test lint`. Expected: pass.
- [ ] **Step 6: Commit** with `git commit -m "feat: back up and restore the entry Xray state"`.

### Task 10: Cloud-lab integration coverage

**Files:**
- Modify: `tests/integration/run.sh`, `tests/integration/lab.yml`, `tests/integration/lab-vars.yml`
- Create: `tests/integration/templates/xray-client.json.j2`

**Interfaces:**
- Consumes: everything above.
- Produces new `run.sh check` names, with `PASS`/`FAIL` evidence in the existing style:
  - `reality_uplink`:
    - `multihop-uplink-xray` listens on the TPROXY port;
    - there is an established TCP connection to the exit's REALITY port;
    - the AWG lab client's egress = exit IP.
  - `reality_throughput`: from the AWG lab client, through the whole path, a 20 s download from a fast URL, e.g. `curl -o /dev/null -w '%{speed_download}' https://speed.cloudflare.com/__down?bytes=99000000`. Record the Mbit/s.
  - `fail_closed_reality_entry_xray`: with `multihop-uplink-xray` stopped, neither the AWG client nor the Xray client reaches the internet. Then start it again.
  - `fail_closed_reality_exit_xray`: the same with `multihop-exit-xray` stopped on the exit.
  - `fail_closed_reality_no_tproxy`: run `iptables -t mangle -F MULTIHOP-TPROXY` on the entry; the AWG client has no internet. Then restore it with `systemctl reload multihop-net` (or however the role re-applies the rules).
  - `icmp_blocked_reality`: `ping -c 3 1.1.1.1` from the AWG client gets no reply.
  - `direct_and_force_exit_reality`: a direct-list destination leaves via the entry IP; a `split_force_exit_cidrs` destination inside a direct range leaves via the exit.
  - `xray_client_via_exit`:
    - add a VLESS client the way the app does: append a client to `server.json`, then `docker restart amnezia-xray`;
    - a stock Xray client container on `CLIENT_IP`, built from `xray-client.json.j2` with a SOCKS inbound, fetches the IP echo URL and gets the exit IP;
    - a direct-list domain gets the entry IP.
  - `xray_restart_keeps_settings`, after `docker restart amnezia-xray` (Review Focus 5):
    - the bind mount is present;
    - `/proc/sys/net/ipv4/ip_local_port_range` excludes `entry_awg_port`;
    - `ss -ti` on an active connection shows `bbr`.
  - `leak_awg_tcp_sport_443`: from the AWG lab client, `curl --local-port 443 <ip echo>` returns the exit IP, and no packet of that flow leaves the entry's public interface towards the echo host (tcpdump on the entry, as the existing checks do).
  - `rollback_to_awg`: re-run `entry.yml` with `uplink_transport=awg`.
    - `multihop-uplink-xray` is gone, `multihop-uplink` is running with endpoint `exit_domain:exit_awg_port`, `MULTIHOP-TPROXY` is absent, and table 51820 has no `local` route.
    - The AWG client's egress is the exit IP.
    - Then switch back to `reality` and re-run `reality_uplink` (Review Focus 2).
  - The existing `swap` check runs in `reality` mode.

- [ ] **Step 1: Implement** the checks and the lab defaults (`uplink_transport: reality`, `entry_xray_enabled: true`).
- [ ] **Step 2: Run on the lab** (owner-provided hosts in `tests/integration/.state/lab.env`): `tests/integration/run.sh init && tests/integration/run.sh deploy && tests/integration/run.sh check && tests/integration/run.sh swap`. Expected: every check PASS. Logs are in `tests/integration/.state/logs/`. If `.state/lab.env` is missing or its hosts are unreachable, report NEEDS_CONTEXT so the controller can ask the owner for lab hosts.
- [ ] **Step 3: App adoption check, done by the owner** on the lab entry with the macOS Amnezia app 5.1.0.6:
  1. Add the server by domain and confirm the app shows XRay as installed, not "update" or "reinstall".
  2. Add a user and connect with the exported `vless://` link in a third-party client.
  3. Report how the app treats the container's Xray release (v26.10.31 vs `expectedServerXrayRelease` v26.7.28).

  If it asks for an update or reinstall, change the vendored Dockerfile's `XRAY_RELEASE` to the release it accepts, re-run, and record the outcome in design section 5.
- [ ] **Step 4: Run** `make test lint`. Expected: pass.
- [ ] **Step 5: Commit** with `git commit -m "test: lab coverage for the Xray uplink and entry Xray"`.

### Task 11: Documentation and example inventory

**Files:**
- Modify: `README.md`, `inventories/example/group_vars/all/vars.yml`, `docs/superpowers/specs/2026-11-03-reality-uplink-and-entry-xray-design.md` (record the Task 1 numbers and the Task 10 app-version result)

- [ ] **Step 1: Update the README.**
  - The architecture diagram shows both transports (`awg` direct; `reality` = TPROXY into Xray, VLESS + REALITY to the exit).
  - New variables table (spec section 9) and updating `xray_image_digest`.
  - `gen-secrets.py xray` for existing vaults.
  - Rule change: the entry runs exactly `amnezia-awg2`, `amnezia-xray`, `multihop-uplink`, `multihop-uplink-xray`.
  - App rules for Xray (spec 8.4): manage only from the 5.1.0.6 desktop app; no port change; no reinstall; site change allowed.
  - Clients (spec 8.5): AWG users change nothing; Xray users need a VLESS client.
  - Swap behaviour: in awg mode the old exit is stopped after the DNS flip, and `stop_old=yes` also disables its restart. In reality mode the entry restarts its Xray after the flip.
  - The exit's AWG port stays public for fast rollback to `uplink_transport: awg`.
  - Troubleshooting commands for the Xray containers.
  - BBR.
- [ ] **Step 2: Add the commented new variables** to `inventories/example/group_vars/all/vars.yml`.
- [ ] **Step 3: Run** `make lint`. Expected: pass.
- [ ] **Step 4: Commit** with `git commit -m "docs: REALITY uplink and entry Xray"`.

### Task 12: Production rollout (operational, owner go-ahead per step)

**Files:** `inventories/prod/group_vars/all/vars.yml` and the vault files (gitignored, not committed).

- [ ] **Step 1: Prepare the secrets and vars.**
  1. `uv run scripts/gen-secrets.py xray`: add both blocks via `uv run ansible-vault edit inventories/prod/group_vars/all/vault.yml`, without writing the plaintext to disk.
  2. Regenerate `vault_uplink.yml` encrypted, as `rotate-uplink-key.yml` does: `uv run scripts/gen-secrets.py uplink-key | uv run ansible-vault encrypt --output inventories/prod/group_vars/all/vault_uplink.yml`. Keep a copy of the old file until Step 4 passes.
  3. In prod `vars.yml`, set `uplink_transport: reality`, `xray_image_digest`, and `entry_xray_enabled: false` (Part 2 comes later).
  4. Pre-check the entry kernel: `ssh root@<entry> modprobe xt_TPROXY` must succeed (entry.yml also loads it before any change and stops if it cannot). Do this before Step 2: if it fails, do not switch.
- [ ] **Step 2: Exit.** `uv run ansible-playbook -i inventories/prod playbooks/exit.yml`. Users lose internet from here until Step 3 finishes, because the AWG uplink key changed. Expect a few minutes.
- [ ] **Step 3: Entry.** `uv run ansible-playbook -i inventories/prod playbooks/entry.yml`, then `uv run ansible-playbook -i inventories/prod playbooks/verify.yml -e verify_fail_closed=true`. Expected: pass.
- [ ] **Step 4: Measure.** The owner runs a speed test on a real device through the AWG profile. Compare it with the old ~1.5 Mbit/s uplink and the ~194 Mbit/s exit limit.
- [ ] **Step 5: Part 2.** Set `entry_xray_enabled: true` and re-run `entry.yml` and `verify.yml`. The owner adds the XRay protocol in the macOS app 5.1.0.6, creates a test user, and confirms it works.
- [ ] **Step 6: Report** the outcomes. Delete the old `vault_uplink.yml` copy and any temporary files.
