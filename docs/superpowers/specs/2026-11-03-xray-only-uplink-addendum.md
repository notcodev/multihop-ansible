# Xray-only uplink — Addendum to the REALITY design

Date: 2026-11-03.

This addendum details section 7.6 of `2026-11-03-reality-uplink-and-entry-xray-design.md`, selected by the gate in 7.0. It replaces sections 7.1–7.4 of that document when `uplink_transport: reality`. Everything else there (BBR, Part 2, backups, variables not mentioned here) stands.

## 1. Why: the gate result (prod, 2026-11-03, exit → entry, BBR, 60 s)

| Shape | 4 streams | 1 stream | Notes |
|---|---|---|---|
| AWG on top of REALITY | 2.36 Mbit/s | 2.71 Mbit/s | 7 of 60 seconds at zero; UDP at 100 Mbit/s lost 96 % |
| Xray-only (TCP straight through VLESS + REALITY) | 196 Mbit/s | 194 Mbit/s | the exit's plan limit |

The AWG run kept `flow: xtls-rprx-vision` on the UDP tunnel, and no variant without it was tried. Given an ~80× gap, the owner's rule decides without a retest.

## 2. Shape

```
ENTRY host                                                                EXIT host
amnezia-awg2 / amnezia-xray ──bridge──▶ PREROUTING (MULTIHOP-MARK)
   reply-marked / direct / local+bridge dst ─▶ main table (unchanged)
   everything else, tcp+udp ─▶ TPROXY → 127.0.0.1:<uplink_tproxy_port>
   everything else, other protocols ─▶ DROP
multihop-uplink-xray (host net, CAP_NET_ADMIN)
   inbound  tunnel, followRedirect, sockopt.tproxy=tproxy, tcp+udp
   outbound VLESS+REALITY → exit_domain:exit_reality_port  ═══▶  multihop-exit-xray (host net)
   (no other outbound)                                              inbound VLESS+REALITY
                                                                    outbound freedom → internet,
                                                                    finalRules block private/CGNAT/
                                                                    link-local/own IP
```

- **Per-connection transport.** Each user TCP connection becomes its own VLESS + REALITY connection with `flow: xtls-rprx-vision`, using BBR on both servers. UDP is carried as XUDP.
- **QUIC.** Vision refuses UDP to port 443 by default, so browsers fall back from QUIC to TCP/TLS. Users notice nothing. That is a TCP connection, which is the better path on this route.
- **No ICMP through the VPN.** Ping from user devices stops working.
- **New-connection latency.** Each new connection costs one REALITY handshake to the exit (about 2 RTT, ~75 ms on Moscow ↔ Frankfurt). Mux is not used, because Vision and mux are incompatible.

## 3. Entry routing and firewall: exact rules

`multihop-entry-net` gets the transport from `multihop.env` (`UPLINK_TRANSPORT`, default `awg`). New env keys:

| Key | Meaning |
|---|---|
| `UPLINK_TPROXY_PORT` | default 12345 |
| `ENTRY_LOCAL_NETS` | the bridges' subnets, e.g. `172.17.0.0/16 172.29.172.0/24`, written by Ansible from `docker network inspect` of `bridge` and `entry_app_network` |

In `awg` mode, nothing below applies and the script behaves exactly as today.

### 3.1 Table 51820 (reality mode)

```
ip route replace local default dev lo table 51820
ip route replace blackhole default metric 4096 table 51820     # unchanged backstop
```

- The `local` route sends every packet routed into the table to local delivery, never to forwarding. The blackhole stays as the backstop if the `local` route is ever missing.
- In `awg` mode, `up` deletes the `local` route, so `default dev awg-uplink` from the uplink container and the blackhole remain.
- The ip rules 10100–10130 are unchanged. Non-direct, non-reply bridge traffic still reaches table 51820 through rule 10130.

### 3.2 `mangle` chains (reality mode)

`MULTIHOP-MARK` (jumped from PREROUTING per bridge, as today) becomes the following. Comments are not part of the rules.

```
-p udp --sport $ENTRY_AWG_PORT -j MARK --set-mark $REPLY_MARK                                   # AWG server (unchanged)
-p tcp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport $ENTRY_XRAY_PORT -j MARK --set-mark $REPLY_MARK   # Task 7, if set
-p udp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport $ENTRY_XRAY_PORT -j MARK --set-mark $REPLY_MARK   # Task 7, if set
-m mark --mark $REPLY_MARK -j RETURN
-m set --match-set multihop_force_exit dst -j MULTIHOP-TPROXY
-m set --match-set multihop_direct dst -j MARK --set-mark $DIRECT_MARK
-m mark --mark $DIRECT_MARK -j RETURN
-j MULTIHOP-TPROXY
```

`MULTIHOP-TPROXY` (new, reality mode only):

```
-m addrtype --dst-type LOCAL -j RETURN
-d <each ENTRY_LOCAL_NETS entry> -j RETURN
-p tcp -j TPROXY --on-ip 127.0.0.1 --on-port $UPLINK_TPROXY_PORT
-p udp -j TPROXY --on-ip 127.0.0.1 --on-port $UPLINK_TPROXY_PORT
-j DROP
```

- In `awg` mode, `MULTIHOP-MARK` keeps today's three rules and `MULTIHOP-TPROXY` does not exist.
- Both chains are built and swapped with the existing `install_chain` pattern. `MULTIHOP-TPROXY` is installed before `MULTIHOP-MARK` references it, and dropped after.
- `MULTIHOP-FWD`, `MULTIHOP-NAT` and `MULTIHOP-MSS` are unchanged. They become partly unused in reality mode, but stay as the backstop.

### 3.3 Why this is fail-closed

A packet from a bridge goes exactly one of these ways:

1. **Reply-marked** (AWG server UDP, or the REPLY direction of a connection DNAT'ed to `entry_xray_port`): rule 10110 → main → public interface. `MULTIHOP-FWD` lets out only these two matches. This is unchanged in kind from today.
2. **Direct-marked** (on the direct list and not force-exit): rule 10100 → main → public interface, allowed by the existing direct-mark FWD rule. Unchanged.
3. **To a local address or a bridge subnet:** RETURN from `MULTIHOP-TPROXY`, then rule 10120 → main → bridge or local. FWD allows bridge-to-bridge traffic; local delivery is not forwarding. Unchanged.
4. **Any other TCP or UDP:** the TPROXY target assigns it to Xray's transparent socket, and rule 10130 → table 51820 → `local` → local delivery to that socket.
   - **Xray not listening:** the TPROXY target finds no socket and the kernel drops the packet (`xt_TPROXY` returns `NF_DROP`).
   - **TPROXY rule missing:** the packet is still delivered locally, through the `local` route, to a socket that does not exist. It gets an RST or ICMP unreachable, never forwarding.
   - **`local` route missing:** the blackhole drops it.
   - In every case the FWD backstop drops anything that still tries to leave a bridge for the public interface.
5. **Any other protocol (ICMP etc.):** DROP in `MULTIHOP-TPROXY`.

Whatever reaches Xray can leave the entry **only** through its single VLESS outbound to the exit. The entry Xray has no `freedom` outbound and no other outbound, so with the exit or the link down, connections fail and nothing leaves via the entry's IP. Xray's own connection to the exit is host traffic (OUTPUT, not PREROUTING from a bridge), so it can never be captured by its own TPROXY.

**Required lab checks** (each must fail to reach the internet, or reach it only via the exit):

- `multihop-uplink-xray` stopped: no internet from either app container.
- `multihop-exit-xray` stopped: none either.
- `MULTIHOP-TPROXY` flushed by hand: none either.
- ICMP to 1.1.1.1 from the AWG client: no reply.
- Direct-list destination: leaves via the entry's IP.
- `force_exit` destination inside a direct-listed range: leaves via the exit.

## 4. Containers and config

- **`multihop-uplink-xray`** (entry):
  - Pinned ghcr image, host network, `user: "0:0"`, capability `NET_ADMIN` (for `IP_TRANSPARENT`), `restart_policy: always`.
  - It is started **after** `multihop-net` (rules), as `multihop-uplink` is today. Until it listens, TPROXY drops packets, so the start order is fail-closed too.
  - Config `xray-uplink.json.j2`:
    - one inbound `tunnel` on `127.0.0.1:{{ uplink_tproxy_port }}`, `settings.network: "tcp,udp"`, `followRedirect: true`, `streamSettings.sockopt.tproxy: "tproxy"`, sniffing off (decisions are IP-based, made on the host);
    - one outbound VLESS + REALITY to `exit_domain:exit_reality_port`, `flow: xtls-rprx-vision`, `fingerprint: chrome`, `serverName: {{ uplink_reality_site }}`, the exit's public key and short id, and the entry's UUID;
    - no `freedom` outbound, no `blackhole` default needed;
    - `policy.levels.0` with a `connIdle` of at least 300 s.
  - The exact field names are checked against the Xray 26 docs (dokodemo/tunnel transparent proxy) and proven on the lab.
- **`multihop-uplink`** (the AWG uplink): **removed** in reality mode, because its PostUp route would compete with the `local` route in table 51820. In `awg` mode it runs as today and `multihop-uplink-xray` is removed.
- **`multihop-exit-xray`** (exit):
  - Pinned ghcr image, host network, `user: "0:0"`.
  - Inbound VLESS + REALITY on `exit_reality_port`, `flow: xtls-rprx-vision`, with fallback limits set.
  - One outbound `freedom` with `finalRules`, in this order:
    1. `block` for the `ip` list `169.254.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, {{ ansible_host }}/32`;
    2. `allow` for everything else.

    This is the same blocked list as `multihop-exit-net`, plus loopback and the exit's own IP.
  - `exit_reality_port`/tcp is open to everyone in `MULTIHOP-IN`.
- **`multihop-exit`** (the AWG exit) **keeps running** in reality mode. It is harmless and lets a rollback to `awg` touch only the entry. The README says so.
- **Egress:** Xray's outgoing connections are host traffic on the exit and leave with the exit's IP. The exit's `MULTIHOP-FWD` and NAT rules for `awg-exit` stay for `awg` mode.

## 5. Identity and secrets (changes to plan Task 2)

| Block | Contents | Notes |
|---|---|---|
| `vault_link_reality` | `{private_key, public_key, short_id}` | The exit's REALITY identity; no UUID. |
| `vault_uplink_entry` (in `vault_uplink.yml`) | gains `reality_uuid` | The entry's credential, so `swap-entry.yml`'s unreachable-entry path (`tasks/rotate-uplink-key.yml`) rotates it together with the AWG uplink key. The exit then accepts only the new UUID. |
| `vault_entry_xray` | unchanged (`{uuid, private_key, public_key, short_id}`) | — |

`gen-secrets.py uplink-key` emits `reality_uuid` too. `gen-secrets.py xray` emits `vault_link_reality` and `vault_entry_xray`.

For the owner's existing prod vault, the rollout regenerates `vault_uplink.yml`. That also rotates the AWG uplink key, so the exit is deployed first, then the entry. Users see a few minutes of interruption, which happens at the switch anyway.

## 6. Re-resolve, swaps and verify

- **`multihop-reresolve`, reality mode:** when the resolved exit IP changes, `docker restart multihop-uplink-xray`, so long-lived connections to the old exit end. The state file is `{{ entry_uplink_state_dir }}/exit-ip`. The public-interface group upkeep is unchanged.
- **`swap-exit.yml`, reality mode:**
  1. After DNS, run `resolvectl flush-caches` on the entry and restart `multihop-uplink-xray`.
  2. Wait (up to 5 min) until the entry has an established TCP connection to `<new exit ip>:<exit_reality_port>`. Generate one, e.g. a request through the IP echo check from `amnezia-awg2`.
  3. Run verify.

  The old exit is not involved: AWG roaming does not exist in this mode. `stop_old` keeps its meaning. The AWG-mode fix from plan Task 6 (stop the old exit before the handshake wait) still applies in `awg` mode.
- **`swap-entry.yml`:** unchanged, apart from the UUID rotation in section 5.
- **`verify.yml`, reality mode:**
  - `multihop-uplink-xray` is running and listens on the TPROXY port.
  - The egress IP seen from `amnezia-awg2` (and from `amnezia-xray`, when enabled) is the exit's IPv4.
  - The exit shows an established connection from the entry's IP on `exit_reality_port`. This takes the place of the `awg-exit` byte counters.
  - Fail-closed (`--tags fail_closed`) stops `multihop-uplink-xray` instead of `multihop-uplink`.
  - The awg-mode checks are unchanged.

## 7. Variables (additions and changes)

| Variable | Default |
|---|---|
| `uplink_transport` | `awg` / `reality` (`reality` now means this Xray-only shape) |
| `uplink_tproxy_port` | 12345 (loopback only; must differ from `entry_xray_port` and SSH) |
| `uplink_reality_local_port` | dropped (no AWG-over-tunnel endpoint) |

## 8. What changes in the plan

- Tasks 4, 5 and 6 are rewritten for this shape. Task 7's Xray reply-exception rules move into the `MULTIHOP-MARK` layout of section 3.2. Task 2 follows section 5.
- Task 10 adds the lab checks from section 3.3 and drops `reality_throughput` through `<uplink .1>`. Instead it measures throughput through Xray from the lab client.
- Task 12 rollout:
  1. Regenerate `vault_uplink.yml` and add `vault_link_reality`/`vault_entry_xray`.
  2. `exit.yml`.
  3. `entry.yml`.
  4. `verify.yml -e verify_fail_closed=true`.
  5. Measure from a real client.
  6. Part 2.
