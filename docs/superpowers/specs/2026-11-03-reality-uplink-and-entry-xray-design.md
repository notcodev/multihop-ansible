# Reality uplink and app-managed Xray on the entry — Design

Date: 2026-11-03. Builds on `2026-10-31-multihop-awg-design.md` (the base design); everything not changed here stays as described there.

## 1. Intent

Users get a fraction of the exit's bandwidth. Measurements on 2026-11-03 (entry in Moscow, exits in another country and then Frankfurt) located the cause on the **entry ↔ exit link**, not on the user hop and not in the exit's CPU:

| Test (exit → entry, the download direction) | Result |
|---|---|
| Plain UDP, no tunnel, 20–100 Mbit/s, ports 5201 / 51822 / 443 / 51821 | 0.1–0.75 % lost (6.6 % at 80 Mbit/s on 51821) |
| AWG 3.1 uplink, in-tunnel UDP 20–50 Mbit/s, on 51821 and on 443 | 13–15 % lost |
| AWG uplink, in-tunnel TCP, 4 streams | 0.4–1.8 Mbit/s |
| Packet count during one test: sent by the exit / reached the entry NIC | 2563 / 1182 |
| Plain TCP, no tunnel, CUBIC, 4 streams | 12–22 Mbit/s, many retransmits |
| VLESS + REALITY (TCP 443, Xray 26.10.31), CUBIC, 1 / 4 streams | 5.5 / 37 Mbit/s |
| **VLESS + REALITY, BBR on both hosts, 1 / 4 streams, 20 s each** | **196 / 197 Mbit/s** (the exit's plan limit) |

Conclusions the design rests on:

- Something on the route (most likely TSPU) recognises the AWG uplink flow and drops about half its packets. The port number does not matter. Plain WireGuard is blocked outright (owner's report). No WireGuard-family protocol is a fix for this link.
- VLESS + REALITY over TCP is not degraded, and moved hundreds of MB per connection without the "stall after ~16 KB" behaviour reported for some foreign hosting ranges.
- The route still has random loss, so the TCP connection carrying the link must use **BBR**. With CUBIC, REALITY alone gets 5–37 Mbit/s.

The owner also wants users to have an Xray (VLESS + REALITY) option on the entry, managed in the Amnezia app like the AWG users are. This is insurance in case AWG gets degraded on the domestic user hop too, and it lets the entry use BBR towards users (with AWG, the TCP sender for a user's download is the remote website, so the entry's congestion control does not matter).

The plain-WireGuard-on-entry idea that started this work is **dropped** (blocked in the owner's network, and it would not touch the slow link).

## 2. Goals

1. **Part 1, REALITY uplink.** The entry ↔ exit link can run inside VLESS + REALITY over TCP, selected by a flag. AWG keeps running on top of it, so routing, fail-closed, split routing, the exit identity, backups and the swap playbooks keep their meaning.
2. BBR (with the `fq` qdisc) is the TCP congestion control on both servers, persistently.
3. **Part 2, entry Xray for users.** Optionally (a flag), the entry also runs the Amnezia app's XRay protocol (`amnezia-xray`, VLESS + REALITY), built by Ansible exactly as the app builds it, so the app adopts it and the owner adds and removes Xray users in the app. Its user state is backed up and restored like the AWG state.
4. Xray users' traffic follows the same path as AWG users' traffic: through the uplink to the exit, except the split-routing direct list. It is fail-closed: with the uplink down, Xray users have no internet, and nothing leaks out of the entry's IP except the defined exceptions.
5. Re-running playbooks never loses users of either protocol.
6. Both parts are verified on real hosts. `verify.yml` and the cloud-lab integration test cover the new modes.
7. Fix the `swap-exit.yml` defect found on 2026-11-03 (section 7.4).

## 3. Non-goals

- Plain WireGuard anywhere (blocked).
- Replacing AWG for users. AWG stays the main user protocol; Xray is additional.
- Building both uplink shapes. The gate in 7.0 picks one: AWG on top of REALITY, or the Xray-only uplink in 7.6.
- Other transports (Hysteria2, xHTTP, gRPC, mKCP, Shadowsocks, Trojan). Hysteria2 runs over UDP, which is what is degraded on this route.
- IPv6 (unchanged from the base design).
- Multiple exits or load balancing.

## 4. Anti-goals (failure even if it "works")

- Any path that lets entry container traffic leave via the entry's public IP outside the defined exceptions. That includes a new exception broad enough to be abused, e.g. "TCP source port 443 from a bridge" would also match an AWG user's TCP flow from source port 443.
- The exit's REALITY inbound acting as an open proxy for anyone holding its UUID. It may forward only to the exit's own AWG port.
- Ansible rewriting app-owned files after first deploy (`server.json`, `clientsTable`, key files of either protocol), or users of either protocol lost on re-run.
- The app failing to adopt `amnezia-xray`, or showing it in a broken or "needs reinstall" state.
- Turning on REALITY mode silently breaking the exit swap, the uplink-key rotation in `swap-entry.yml`, or `verify.yml`.

## 5. Constraints

- Xray versions:
  - **Target app: Amnezia 5.1.0.6** (tag `5.1.0.6`, commit `ac175c8`). The owner manages the server from the macOS desktop app 5.1.0.6. The iPhone app is still on 5.0.3.0 (no iOS build yet) and is used only as a client, not for managing Xray users. `ac175c8` is 2 commits after `7f9b7db`, the source that sections 6 and 8 were researched against. Those 2 commits change, for Xray, only the Dockerfile's Xray release and the client fingerprint default (`hellochrome_120`). For AWG they change only a default in new-install parameter generation, so the vendored AWG container is unaffected.
  - The `amnezia-xray` image is the app's own Dockerfile from `ac175c8`, which installs Xray `v26.10.31`. **Open point for the builder:** the same commit still has `expectedServerXrayRelease = "v26.7.28"`. On a lab entry, the owner adds the server in the macOS app 5.1.0.6 (the builder cannot drive the app) and reports how it reacts to a v26.10.31 server: adopt silently, or offer an update or reinstall. Ship the release that the app adopts without asking, and record the result in this document.
  - The uplink containers use the official `ghcr.io/xtls/xray-core` image pinned by digest, like `awg_base_image_digest`.
  - The REALITY spike used `26.10.31`.
  - The ghcr image runs as non-root, and binding 443 needed `--user 0:0` or `NET_BIND_SERVICE`.
- Xray 26's `freedom` outbound **blocks loopback and private destinations by default**. In the spike, a forward to `127.0.0.1` was blackholed. The exit's forward to its own AWG port must use a destination freedom allows, or the documented override, and nothing broader.
- REALITY's client side must not have `target`; its presence makes Xray treat a config as server-side.
- The REALITY target site must support TLS 1.3 + H2 and not redirect. `dl.google.com` passed `xray tls ping` from the Frankfurt exit (TLS 1.3, X25519MLKEM768) and was used in the spike.
- The app rewrites the whole `server.json` from its own model when Xray settings change in the app. It rewrites only the `clients` array when users are added or removed. It always writes a single VLESS inbound plus a `freedom` outbound. So nothing Ansible needs may live in `server.json` beyond what the app itself writes. Routing of Xray users must be done on the host, as it is for AWG.
- Both servers are Ubuntu 26.04 (accepted by the owner; the base design says 24.04), x86_64, 2 vCPU class.

## 6. How the Amnezia app sees an Xray server (from source at `7f9b7db`)

Files: `client/server_scripts/xray/{Dockerfile,configure_container.sh,run_container.sh,start.sh}`, `client/core/configurators/xrayConfigurator.cpp`, `client/core/models/protocols/xrayProtocolConfig.cpp`, `client/core/installers/xrayInstaller.cpp`, `client/core/controllers/selfhosted/usersController.cpp`, constants in `client/core/utils/constants/protocolConstants.h`.

- **Container `amnezia-xray`:**
  - `--privileged --cap-add=NET_ADMIN --restart always --log-driver none`.
  - Publishes `$XRAY_SERVER_PORT` on both tcp and udp (default port 443).
  - Its state lives in the named volume `amnezia-xray-data` mounted at `/opt/amnezia/xray`.
  - Attached to the default bridge, then `docker network connect amnezia-dns-net`.
  - Creates `/dev/net/tun` inside.
- **`start.sh`:**
  - Sets INPUT rules inside the container (allows 80, 443 and the Xray port, then policy DROP; IPv6 likewise).
  - Runs `xray -config /opt/amnezia/xray/server.json` if the file exists.
- **Key files in `/opt/amnezia/xray/`:** `xray_uuid.key`, `xray_private.key`, `xray_public.key`, `xray_short_id.key` (16 hex chars). `configure_container.sh` creates each only when missing, by content.
- **`server.json` as the app writes it:**
  - `log.loglevel: error`.
  - One inbound: `port`, `protocol: vless`, `settings.clients` (each client is `{id, flow}` with `flow: xtls-rprx-vision`), `settings.decryption: none`.
  - `streamSettings` with `security: reality`. Its `realitySettings` holds `dest: <site>:443`, `serverNames: [<sni or site>]`, `privateKey`, `shortIds: [<short id>]`.
  - One outbound, `freedom`.
  - The default site is `www.googletagmanager.com`.
- **The server's own UUID** (`xray_uuid.key`) is the first client in `server.json`. The users table logic strips that UUID from `clientsTable`.
- **User management:** the app reads `server.json`, edits `inbounds[0].settings.clients`, uploads it, and runs `docker restart amnezia-xray`. `clientsTable` lives in the same directory.
- **Issued keys keep the hostname.** For AWG, WireGuard and Xray, the app does not resolve the server name to an IP (`client/core/utils/selfhosted/scriptsRegistry.cpp:144`, `genBaseVars`). So with the server added by `entry_domain`, Xray keys survive an entry swap exactly like AWG keys. Only the DNS record moves.
- **Version check.** The app compares the container's Xray binary with `expectedServerXrayRelease` (`installController.cpp`, around line 110) and treats a mismatch as needing an update. That is why the image must match the app version the owner runs (section 5).

The builder must re-read these files before implementing, as was done for AWG in the base design. Anything above that turns out wrong in detail is a fact to correct in this document, not a design choice.

## 7. Part 1: REALITY uplink

### 7.0 Gate: measure AWG over REALITY before building

The 196 Mbit/s result was a plain TCP stream through REALITY. The planned shape, AWG UDP carried inside one VLESS connection, was not measured. Before any role work:

1. Run a throwaway setup on prod in the exact shape of 7.1:
   - Xray containers on both servers.
   - A second, temporary AWG interface pair on a spare subnet, carried through the Xray tunnel.
   - BBR on both servers.
   - The real uplink and users are not touched.
2. Measure `iperf3 -R` TCP through that AWG pair: 1 and 4 streams, 60 s each. Also measure a UDP loss run, and check per-second results for stalls.
3. Under the same conditions, measure the Xray-only shape: TCP carried straight through VLESS + REALITY, as in the 2026-11-03 spike. Re-measuring it in the same session gives a fair baseline (196 Mbit/s that day).
4. **The owner's rule: the gate decides the uplink shape.**
   - **AWG on top of REALITY** (this design, 7.1–7.4) if all of these hold:
     - 4 streams reach at least 150 Mbit/s;
     - 4 streams reach at least 75 % of the Xray-only number from step 3;
     - no second over the 60 s drops to zero.
   - **Xray-only uplink** (7.6) otherwise.
5. Clean up everything, then report the numbers and the outcome to the owner.

**Known risk of the shape:** all users share one long-lived TCP connection. If something on the route cuts long-lived foreign flows, everyone stalls until Xray reconnects. The 60 s run and the first days in production show whether that happens. If it does, periodic reconnects or several connections are the builder's first remedies.

### 7.1 Shape

```
ENTRY host                                                     EXIT host
multihop-uplink (AWG, host net)                                multihop-exit (AWG, host net)
  awg-uplink  Endpoint = 127.0.0.1:<uplink_reality_local_port>   awg-exit listens exit_awg_port/udp
        │ UDP                                                          ▲ UDP
        ▼                                                              │
multihop-uplink-xray (host net)                                multihop-exit-xray (host net)
  inbound  tunnel 127.0.0.1:<local port>, UDP only               inbound  VLESS+REALITY tcp/<exit_reality_port>
  outbound VLESS+REALITY → exit_domain:<exit_reality_port> ════▶ outbound freedom → only <exit AWG port>
```

- Flag `uplink_transport: awg | reality`.
  - `awg` is today's behaviour, unchanged.
  - `reality` sets the AWG uplink peer's `Endpoint` to the local Xray tunnel port. AWG's own parameters (`vault_link_awg`) stay as they are.
- AWG packets travel inside one VLESS connection as UDP (Xray's UDP over VLESS). `PersistentKeepalive = 25` keeps the Xray UDP session alive. The builder checks that the Xray UDP idle timeout is longer than that, or sets it.
- Users notice nothing when the transport changes, except a short interruption.

### 7.2 Exit side

- **New container `multihop-exit-xray`:**
  - Host network, pinned ghcr image, `restart: always`.
  - Config rendered from the vault.
  - Inbound VLESS + REALITY on `exit_reality_port` (default 443) with `flow: xtls-rprx-vision`.
- **Forwarding:** Xray routing allows only UDP to the exit's own AWG port. Everything else is blocked (anti-goal 4). The destination address follows the constraint in section 5. The spike reached the exit's own public IP; `127.0.0.1` was blocked by default.
- **Firewall:** `exit_reality_port`/tcp is opened in `MULTIHOP-IN` to everyone, not only to the entry. Probes from anyone must see the target site through REALITY's fallback, because a closed port looks different from a real website.
- **The exit's REALITY identity is in the vault:** private key, public key, short id, UUID. A new exit is therefore identical and needs no entry change, as with AWG today.
- **Fallback abuse:** REALITY forwards failed authentications to `target`, so the exit can be used as a free relay to the target site. The builder sets `limitFallbackUpload`/`limitFallbackDownload` to modest values; the defaults are the builder's call.
- **The direct AWG port:** in `reality` mode the exit's AWG port is reached only through Xray. Whether it stays open publicly is the builder's call. Closing it is cleaner. Keeping it allows a quick fallback to `uplink_transport: awg`, and the README must then say so.

### 7.3 Entry side

- **New container `multihop-uplink-xray`:**
  - Host network, pinned ghcr image.
  - A `tunnel` inbound on `127.0.0.1:<uplink_reality_local_port>`, UDP only, rewriting to the exit's AWG address and port as seen from the exit's Xray.
  - A VLESS + REALITY outbound to `exit_domain:exit_reality_port`, with `fingerprint: chrome`, `serverName` = the REALITY site, and the exit's public key and short id.
- **Xray's own TCP connection to the exit is host traffic.** Like `multihop-reresolve` and the image pulls, it leaves via the public interface through the main table. The builder confirms that no rule (10100–10130, `MULTIHOP-FWD`) catches it, and that the entry's input firewall lets its replies in (ESTABLISHED).
- **`multihop-reresolve`:** in `reality` mode it must not reset the AWG endpoint to `<exit IP>:<port>`. The AWG endpoint is fixed at `127.0.0.1`, and Xray resolves `exit_domain` on each new connection. What the timer does instead is the builder's call. One option: detect a changed IP and restart `multihop-uplink-xray`, so a swap takes effect without waiting for the long-lived connection to break.
- **Fail-closed is unchanged:** with Xray or the exit down, AWG has no handshake, so table 51820 has no usable route and bridge traffic is dropped. The builder verifies this with the existing fail-closed check (stop `multihop-uplink-xray` and expect no internet from the app containers).
- **MTU:** the outer link is TCP, so the 1280 uplink MTU is no longer forced by UDP encapsulation. Keep 1280 unless the builder measures a clear gain with a larger value.

### 7.4 Swap playbooks

- `swap-exit.yml` in `reality` mode:
  - It cannot use "uplink endpoint == new exit IP". It must check the Xray connection's remote address, or the handshake after an Xray restart.
  - It must restart `multihop-uplink-xray` after DNS resolves to the new IP.
  - It must account for the entry's own resolver cache. On 2026-11-03 the entry's systemd-resolved served the old IP for minutes after public resolvers had the new one, until `resolvectl flush-caches`.
- **Defect found on 2026-11-03, to fix in both modes:**
  - With the old exit still carrying traffic, the entry's AWG peer keeps roaming back to the old exit's IP, because both exits share the same keys. So the "handshake with the new exit" wait can never succeed before `stop_old` runs at the very end.
  - The fix is the builder's call. Either stop the old exit before the wait when `stop_old=yes`, or make the old exit stop accepting the entry once DNS has flipped. The playbook must not hang or fail in this situation, and the README must describe the actual behaviour.
- `swap-entry.yml`:
  - REALITY credentials are exit-side identity and do not rotate with the uplink key.
  - The new entry must get `multihop-uplink-xray` before the uplink can come up.

### 7.5 BBR

- `net.core.default_qdisc = fq` and `net.ipv4.tcp_congestion_control = bbr`, persistent (`/etc/sysctl.d/`), on both servers, in both transport modes (cheap, and it helps host TCP generally).
- `tcp_congestion_control` is per network namespace. The builder verifies, with `ss -ti`, that connections of the `amnezia-xray` container (its own netns) use BBR. If they don't, set it on that container with `--sysctl net.ipv4.tcp_congestion_control=bbr`. Containers on the host network inherit the host value.

### 7.6 Xray-only uplink (used only if the gate in 7.0 selects it)

**Why it might win.** With AWG on top, every user's TCP travels inside one outer TCP connection: TCP over TCP, with head-of-line blocking. One lost segment stalls every user for about a round trip, and one cut connection drops everyone. Xray-only removes both problems:

- The entry intercepts each user flow and Xray carries it in its own VLESS + REALITY connection to the exit. TCP is split into three legs, so the cross-border leg gets its own BBR, and loss on one connection does not stall the others.
- There is one layer of encryption, not two.

**Shape:**

- **Entry:**
  - `multihop-uplink-xray` (host network) runs a TPROXY (transparent-proxy) inbound for TCP and UDP.
  - Bridge traffic that is not direct-marked is diverted into it by the mangle-table TPROXY target plus a local-delivery routing rule. This takes the place of rules 10130 and table 51820.
  - The outbound is VLESS + REALITY to the exit.
- **Exit:**
  - `multihop-exit-xray` sends traffic out through `freedom` to the internet. It no longer only forwards to the AWG port.
  - The exit's existing user-traffic filters must be re-implemented for the Xray process: drop private, CGNAT and link-local destinations.
  - The AWG exit container is not needed in this mode.
- **No ICMP:** ping through the VPN stops working. TCP and UDP (including QUIC) work.

**Requirements carried over unchanged:**

- **Fail-closed:** with Xray or the exit down, nothing from the bridges leaves via the entry's IP except the defined exceptions. Non-direct traffic must have no path except the TPROXY socket, and dies if that socket is absent.
- Split routing (direct and force-exit sets) is decided before interception.
- The reply exceptions of 8.2 stay.
- The DNS behaviour of the containers is unchanged.

**Approval.** This rewrites the security-critical part of the base design, `multihop-entry-net`, and with it its bats tests, `verify.yml`, both swap playbooks and the exit role. Before building it, the builder writes a short addendum with the exact rule set and the fail-closed argument, and gets the owner's approval. The gate decides the direction; the addendum covers the details. Part 2 and BBR do not depend on which shape wins.

## 8. Part 2: app-managed Xray on the entry

### 8.1 Container and state

- Flag `entry_xray_enabled` (default `false` in the role). `entry_xray_port` defaults to 443 (the app's default).
- **Image:** vendor `client/server_scripts/xray/Dockerfile` and `start.sh` from `ac175c8` (app 5.1.0.6; see section 5 for the release check), the same way the AWG Dockerfile was vendored (note the commit and the minimal changes in a header comment). `$XRAY_SERVER_PORT` is substituted in `start.sh`.
- **Run `amnezia-xray` like `run_container.sh`,** with one deliberate difference: the state is a **host bind mount** `/var/lib/multihop/entry-xray` → `/opt/amnezia/xray`, not the named volume. This is the same choice as for AWG, for backups and drift detection. The `/dev/net/tun` creation step is kept.
- **Seed on first deploy only** (when `server.json` is absent):
  - Key files from the vault (`vault_entry_xray`: uuid, private key, public key, short id, generated by `gen-secrets.py`).
  - `server.json` byte-for-byte in the app's structure (section 6), with the server UUID as the only client and the REALITY site from `entry_xray_site`.
  - After that, Ansible never touches these files again, nor `clientsTable`.
- **Reality site for the entry:** `entry_xray_site`, default the app's `www.googletagmanager.com`. A domestic site might look more natural for a Moscow IP. That is the owner's call and can also be changed later in the app (section 8.4).
- **Port conflict:** `entry_xray_port` must differ from every other port the entry listens on (SSH, AWG UDP).

### 8.2 Routing and fail-closed

- `amnezia-xray` sits on the same bridges as `amnezia-awg2` (default bridge and `amnezia-dns-net`), so its outgoing connections, which are its users' traffic, already follow rules 10100–10130: the direct list leaves via the entry, everything else goes through the uplink, and they are dropped when the uplink is down.
- **New exception:** replies from the Xray server to its users must leave via the entry's IP. The requirement:
  - Only packets belonging to connections that came **in** on the published `entry_xray_port` (tcp, and udp since the app publishes both) get the reply mark and pass `MULTIHOP-FWD` to the public interface.
  - That must stay true even if an AWG user, or an Xray user's outgoing flow, uses source port 443.
  - A bare `--sport 443` match fails this. Matching conntrack's original direction does not (e.g. `-m conntrack --ctdir REPLY --ctorigdstport <entry_xray_port>`, plus the original destination being the entry's address or the container's DNAT target). The exact match is the builder's call; the requirement is not.
- **The existing AWG exception must be narrowed (required, found in review).** Today it matches "UDP from a bridge with source port `entry_awg_port`" (51820 on prod).
  - Port 51820 lies inside Linux's default ephemeral range. An outgoing UDP flow of `amnezia-xray`'s users could therefore get source port 51820 and leave via the entry's IP.
  - The match must be limited to `amnezia-awg2`'s own traffic, for example by that container's address on each bridge (fixed or looked up), or by conntrack original direction.
  - The same applies to `amnezia-xray`'s exception in the other direction.
  - The leak test in section 10 covers both.
- The base design's `README` rule "the entry runs only `amnezia-awg2` and `multihop-uplink`" becomes: the entry runs only `amnezia-awg2`, `amnezia-xray`, `multihop-uplink` and `multihop-uplink-xray`.

### 8.3 Backups, drift, restore

- **Backups** include the Xray state directory. How it sits in the archive is the builder's call, for example a subdirectory, or a second archive in the same backup. Keep the change-only behaviour.
- **Drift:**
  - `amnezia-xray` without the bind mount is drift, handled like the AWG case (exit code 2, `DRIFT` file, `entry.yml` fails with recovery instructions).
  - Drift on one protocol must not stop the other protocol's state from being backed up.
- **Restore validation:**
  - `server.json` must parse as JSON and match the app's shape: one VLESS inbound on `entry_xray_port` with REALITY, and only a `freedom` outbound.
  - No other inbounds, outbounds, `routing`, `api` or `stats` sections.
  - Key files must be single-line values of the right form.
  - Reject anything else, as `awg0.conf` validation does today.
- `swap-entry.yml` and `restore.yml` carry the Xray state along with the AWG state.

### 8.4 What the owner may and may not do in the app

- **Adding and removing Xray users** in the app is the normal path.
- **Changing the Xray site/SNI in the app** is allowed: the app regenerates `server.json` with its own structure, which keeps validation and routing intact.
- **Changing the Xray port in the app is forbidden.** The published port, the reply exception and the firewall are built from `entry_xray_port`. Same as the AWG rule.
- **"Remove / reinstall protocol" for Xray is forbidden.** It recreates the container on a named volume: drift, plus new keys, so every issued Xray key stops working. Same as AWG.
- **Manage Xray only from the app version this is built for** (5.1.0.6 on macOS). Older apps write the Xray server config differently.
- The README gets these rules.

### 8.5 Clients

- **Existing AWG users change nothing.** Their keys and clients, including the standalone AmneziaWG app, keep working, and they get the Part 1 speed-up because it is server-side.
- **Xray users need a VLESS + REALITY client.** The AmneziaWG app cannot be used. For each Xray user the Amnezia app exports a `vless://` link and an Xray JSON config (`exportController.cpp`, `generateXrayConfig`). Standard clients take either one, for example Streisand, V2Box, Hiddify or Happ on iOS; v2rayNG, Hiddify or Happ on Android; Hiddify or v2rayN on desktop.
- The README lists this. The lab test checks that the exported `vless://` link works in a stock Xray client.

## 9. Variables and secrets

| Variable | Where | Default |
|---|---|---|
| `uplink_transport` | vars | `awg` in roles (unchanged behaviour for existing inventories); the owner's prod inventory sets `reality` |
| `exit_reality_port` | vars | 443 |
| `uplink_reality_site` | vars | `dl.google.com` (tested) |
| `uplink_reality_local_port` | vars (role default) | builder's choice, loopback only |
| `xray_image_digest` | vars | pinned `ghcr.io/xtls/xray-core` digest; README documents updating it like `awg_base_image_digest` |
| `entry_xray_enabled` | vars | `false` |
| `entry_xray_port` | vars | 443 |
| `entry_xray_site` | vars | `www.googletagmanager.com` |
| `vault_link_reality` | vault | `uuid`, `private_key`, `public_key`, `short_id`; generated by `gen-secrets.py all`; existing vaults get a new subcommand to add just this block |
| `vault_entry_xray` | vault | `uuid`, `private_key`, `public_key`, `short_id`; seeds the first deploy only |

`vault.yml.example` and the README document both blocks with fake values.

## 10. Verification

- **`verify.yml`:**
  - In `reality` mode: `multihop-uplink-xray` and `multihop-exit-xray` are running, an AWG handshake through them, and egress IP = exit.
  - With `entry_xray_enabled`: `amnezia-xray` is running with the bind mount, listening on `entry_xray_port`.
  - The fail-closed check also stops `multihop-uplink-xray` in `reality` mode.
- **Throughput check** (manual or a tagged task): `iperf3 -R` from the entry to the exit's uplink address. It should come out near the exit's plan limit, compared with ~1.5 Mbit/s for the current AWG uplink on this route.
- **Cloud-lab integration test:**
  - Covers `uplink_transport: reality`, including the exit swap, and `entry_xray_enabled`.
  - Includes a test VLESS client added the way the app adds one (new client in `server.json`, then `docker restart amnezia-xray`), checking that its traffic exits via the exit IP and that the direct list goes direct.
  - Includes leak checks:
    - AWG-user TCP from source port 443 must not leave via the entry IP.
    - Xray-user UDP from source port `entry_awg_port` must not leave via the entry IP either.
- **Unit and render tests** cover the new templates, the restore validation and `gen-secrets.py`.

## 11. Rollout on the owner's production

Before step 3, the owner installs the macOS Amnezia app 5.1.0.6 and re-adds or refreshes the server in it.

The builder (Claude, with the owner's go-ahead per step) runs these steps on `entry1` (147.45.212.14) and `exit2` (213.182.213.237). The lab cannot reproduce the filtering on this route, so the throughput goal can only be proven on prod. `exit1` (195.216.169.41, in `exit_old`) is stopped with its restart policy off, so it carries no traffic. The in-app adoption check needs the owner's Amnezia app and is done by the owner: add the Xray protocol and create a test user.

0. Run the gate in 7.0.
1. Deploy `multihop-exit-xray` on the exit. The AWG link stays direct and nothing changes for users.
2. Switch the entry to `uplink_transport: reality` (a short interruption). Verify, measure throughput, then decide about the exit's public AWG port.
3. Enable `entry_xray_enabled`. Add the server's Xray protocol in the app and create a test user. Verify.

## 12. Decisions made by the designer (not explicitly by the owner)

- AWG on top of REALITY is the default shape. The owner decided that the gate picks the shape (7.0). The thresholds (150 Mbit/s, 75 % of Xray-only, no zero second) are the designer's.
- BBR on both servers in both modes.
- The role default `uplink_transport: awg`, with prod set to `reality`.
- `dl.google.com` as the uplink REALITY site, and the app default site for the entry.
- The exit's REALITY port is open to everyone, not only the entry.
- A bind mount instead of the app's named volume for `amnezia-xray`, mirroring the AWG choice.
- The `swap-exit.yml` defect is fixed as part of this work.
- Xray port changes and protocol reinstall in the app are forbidden; site changes in the app are allowed.
- If the gate selects Xray-only, a short addendum with the exact rules gets the owner's approval before building.
- The narrowed AWG exception (8.2) is part of this work, not a separate fix.
