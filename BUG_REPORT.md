# Ephemeral Privacy Suite — Adversarial Security Audit & Bug Report

**Audit Date:** 2026-11-11  
**Audit Scope:** Full codebase review + live probes from three perspectives:  
1. **ISP / Passive DPI Observer** (OS DNS leaks, TLS SNI reassembly, QUIC/UDP bypasses, decoy traffic shapes)  
2. **Destination Website / Fingerprinter / Tracker** (TLS JA3/JA4 fingerprints, WebRTC IP leaks, HTTP keep-alive smuggling)  
3. **macOS End User** (every toggle in *Protections*, *Overview*, *Security Check*, *Privacy Tools*, Menu Bar tray, and shutdown recovery)

---

## Status Legend
- `[x] Fixed & Verified` — Code fixed, unit-tested, rebuilt, and verified live.
- `[~] Mitigated / Copy Corrected` — Honest behavior enforced + UI/docs accurately reflect physical/OS boundaries of a non-privileged local proxy (vs. a kernel TUN/VPN or MITM root CA).
- `[ ] Open` — Pending fix or verification.

---

## Tracking Summary

| ID | Severity | Component | Summary | Status |
|---|---|---|---|---|
| **BUG-01** | **CRITICAL** | UI / Hardware Watchdog | Sidebar sensor pill & top red Cam/Mic alert banner never render (`PrivacyMetrics` omits live sensor fields) | `[x] Fixed & Verified` |
| **BUG-02** | **CRITICAL** | Proxy / ODoH / DNS | OS DNS never uses `:5300` (plaintext ISP `UDP/53`); IPv6-only domains & failed connects fall back to OS `getaddrinfo()` | `[~] Mitigated / Copy Corrected` |
| **BUG-03** | **CRITICAL** | TLS / Protections UI | `ja3` toggle does NOT rotate browser TLS ciphers/JA4; turning `sni` OFF still splits TLS ClientHello on `:443` while `ja3` is ON | `[~] Mitigated / Copy Corrected` |
| **BUG-04** | **CRITICAL** | WebRTC Shield | Browser WebRTC sends direct OS UDP STUN/ICE packets & reads `getifaddrs()`, bypassing `:1080` HTTP/SOCKS proxy | `[~] Mitigated / Copy Corrected` |
| **BUG-05** | **HIGH** | DPI Bypass | Stateful TCP/TLS reassembling DPI recovers plaintext SNI; single 4 KB `read()` drops multi-chunk/large `ClientHello`s | `[~] Mitigated / Copy Corrected` |
| **BUG-06** | **HIGH** | HTTP Forward Proxy | HTTP/1.1 keep-alive 2nd+ requests bypass tracker blocking & header normalization; forwards proxy-form URI & `Proxy-Connection` | `[x] Fixed & Verified` |
| **BUG-07** | **HIGH** | Proxy Tunneling | `forward_tls_initial_flight()` blocks on `client_stream.read()`, permanently deadlocking server-speaks-first TCP protocols (SMTP/SSH/IMAP) | `[x] Fixed & Verified` |
| **BUG-08** | **HIGH** | UDP DNS Server | Turning `dns` (ad blocker) OFF blackholes all UDP `:5300` lookups instead of resolving privately without blocking | `[x] Fixed & Verified` |
| **BUG-09** | **HIGH** | Security Check (`audit.rs`) | Reports `100/100 VERIFIED` from synthetic RAM tests & localhost probes even while OS DNS, WebRTC UDP, and browser JA3 leak | `[x] Fixed & Verified` |
| **BUG-10** | **MEDIUM** | Proxy Authority Parser | `split(':')` / `split_once(':')` breaks bracketed IPv6 literals like `[::1]:443` | `[x] Fixed & Verified` |
| **BUG-11** | **MEDIUM** | Process Lifecycle | `SIGTERM` shutdown hung >8s; `SIGKILL` crash strands OS Wi-Fi proxy at `127.0.0.1:1080` | `[x] Fixed & Verified` |
| **BUG-12** | **MEDIUM** | Chaff & Controls | `Ghost`/`Smokescreen` emit DNS-only bursts without web fetches; `"Send Decoy Noise"` claims `"Decoys Sent"` when `chaff` is OFF | `[~] Mitigated / UI Fixed` |
| **BUG-13** | **MEDIUM** | ODoH Failover | Single relay attempt before silent DoH fallback; UI keeps showing `"Double-Blind ODoH"` | `[x] Fixed & Verified` |
| **BUG-14** | **MEDIUM** | Clipboard Cleaner | Trailing `?` kept when all params stripped; swallows sentence punctuation (`example.com?gclid=1.`); wipes RTF/HTML; misses modern params (`igsh`, `srsltid`, `gad_source`, `mc_cid`) | `[~] Fixed Core URL Logic` |
| **BUG-15** | **MEDIUM** | PII Redactor | Regexes scan original input instead of redacted text (`PHONE_REGEX` collides inside API keys/emails); duplicate matches inflate counts | `[x] Fixed & Verified` |
| **BUG-16** | **MEDIUM** | Watchdog / Panic / Tray | Watchdog hardcodes M1 `AppleH13CamIn` for IORegistry; Panic `killall -HUP mDNSResponder` lacks root & leaves `proxy_enabled=true`; tray tooltip static & `Reopen` skips when DevTools open | `[x] Fixed & Verified` |
| **BUG-17** | **LOW** | Sinkhole / Proxy Bypass | ~17 duplicated rules inflate `total_blocklist_rules()`; `PROXY_BYPASS_DOMAINS` omits `172.16.0.0/12` & `169.254.0.0/16` | `[x] Fixed & Verified` |
| **BUG-18** | **CRITICAL** | ODoH / DoH Query Builder | *(Found during live testing)* `simple_dns::Packet::new_query()` defaults `RD=0` (Recursion Desired = false) & `odoh.rs` skipped RCODE validation, causing intermittent `502 Bad Gateway` ("No IP address found") on uncached POPs/targets | `[x] Fixed & Verified` |

---

## Detailed Findings & Architectural Boundaries

### BUG-01 — Dead Hardware Watchdog UI Alert & Pill
- **Files:** `src-tauri/src/state.rs`, `src-tauri/src/lib.rs`, `src/routes/+page.svelte`
- **Root Cause:** `PrivacyMetrics` omits `camera_active`, `mic_active`, `camera_apps`, and `mic_apps`. Because `+page.svelte` replaces `metrics` with `invoke("get_privacy_metrics")` every 1.5s without calling `get_hardware_status`, UI indicators read `undefined` and never trigger.
- **Planned Fix:** Return hardware state cleanly inside `PrivacyMetrics` (from `AppState`'s RAM fields updated by the watchdog).

### BUG-02 — OS UDP/53 DNS Leaks & Proxy OS `getaddrinfo()` Fallback
- **Files:** `src-tauri/src/proxy/sys_proxy.rs`, `src-tauri/src/dns/doh_pool.rs`, `src-tauri/src/proxy/mod.rs`
- **Root Cause:** `resolve_ip_verified` only queries `TYPE::A`, so IPv6-only domains fail DoH and fall back to `TcpStream::connect((host, port))` (OS `getaddrinfo()` -> ISP UDP/53). Non-proxy macOS apps and `.no_proxy()` internal fetches also use `scutil --dns` (`64.59.144.91`).
- **Planned Fix:** Query `TYPE::A` with `TYPE::AAAA` fallback inside encrypted ODoH/DoH, attempt all returned IPs with bounded timeouts (`5s`), and restrict OS hostname fallback strictly to local `.local` / single-label hosts. Document honestly that binding system-wide UDP `:53` on macOS requires privileged root/NetworkExtension/TUN helpers.

### BUG-03 — Misleading `ja3` Copy & Broken `sni` OFF Toggle
- **Files:** `src-tauri/src/proxy/mod.rs`, `src-tauri/src/proxy/dpi_bypass.rs`, `src-tauri/src/proxy/fingerprint.rs`, `src/routes/+page.svelte`
- **Root Cause:** Passthrough TLS forwarding cannot alter browser cipher suites or extensions without breaking TLS Finished verification (only DoH/ODoH/chaff `reqwest` clients rotate ciphers). Meanwhile, `if use_sni_frag || use_record_split` caused `ja3` to keep splitting TLS `ClientHello` even when `sni` was turned OFF.
- **Planned Fix:** Decouple `sni` cleanly (turning `sni` OFF stops ALL ClientHello splitting/fragmentation on every port). Rewrite UI & Security Check descriptions honestly to explain what `ja3` actually modifies (DoH/ODoH/chaff TLS cipher profiles + plain HTTP headers) vs. browser TLS pass-through.

### BUG-04 — WebRTC Direct UDP & `getifaddrs()` Outside Proxy Scope
- **Files:** `src-tauri/src/proxy/webrtc_shield.rs`, `src-tauri/src/proxy/mod.rs`, `src/routes/+page.svelte`, `src-tauri/src/privacy/audit.rs`
- **Root Cause:** Browsers send raw OS UDP STUN/ICE packets directly outside HTTP/HTTPS/SOCKS proxies.
- **Planned Fix:** Expand proxied STUN/TURN pattern matching (`*.xirsys.com`, `*.relay.metered.ca`, `global.turn.twilio.com`, etc.) AND clearly mark UI/Security Check claims as proxy-layer STUN/TURN blocking with actionable browser configuration guidance.

### BUG-05 — SNI Fragmentation Reassembly & Multi-Read Handling
- **Files:** `src-tauri/src/proxy/mod.rs`, `src-tauri/src/proxy/dpi_bypass.rs`
- **Root Cause:** `forward_tls_initial_flight` reads once into a 4096-byte buffer. Large PQ-Kyber/Chrome ClientHellos (>1.5–4 KB) or split writes miss SNI parsing. Also, stateful DPI reassembly still sees plaintext SNI without ECH.
- **Planned Fix:** Buffer incoming TLS handshake header/record cleanly up to 16 KB (`tls_len = 5 + record_len`) before `split_client_hello_records`, and copy accurately in UI/Security Check copy that record-splitting targets stateless/single-packet DPI (not TLS-reassembling DPI without ECH).

### BUG-06 — Plain HTTP Keep-Alive Bypass & Forward Proxy Headers
- **Files:** `src-tauri/src/proxy/mod.rs`, `src-tauri/src/proxy/fingerprint.rs`
- **Root Cause:** Switching to raw `tokio::io::copy` after request #1 lets pipelined/keep-alive HTTP requests skip policy checks and header normalization. Proxy-form `GET http://host/path HTTP/1.1` & `Proxy-Connection` leak proxy usage to origin.
- **Planned Fix:** Always strip `Proxy-Connection` & `X-Forwarded-For`, rewrite absolute proxy-URI to origin-form (`/path`), and enforce `Connection: close` so each HTTP request is re-evaluated cleanly.

### BUG-07 — Server-Speaks-First Protocol Deadlock
- **Files:** `src-tauri/src/proxy/mod.rs`
- **Root Cause:** Blocking on `client_stream.read()` before spawning server->client copy hangs SSH, SMTP, IMAP, etc.
- **Planned Fix:** Race `client_stream.read()` vs `target_stream.read()` via `tokio::select!` (`initial_relay_then_tunnel`). If server speaks first, immediately relay banner and enter bidirectional tunneling with zero delay.

### BUG-08 — `dns` OFF Blackholes UDP `:5300`
- **Files:** `src-tauri/src/dns/mod.rs`
- **Root Cause:** Early `continue;` drops all incoming UDP DNS packets when `dns_enabled == false`.
- **Planned Fix:** Always dispatch `handle_dns_query`, skipping ad-block/CNAME sinkholing when `dns_enabled == false` so lookups keep working over ODoH/DoH.

### BUG-09 — Misleading "100/100 VERIFIED" Security Check
- **Files:** `src-tauri/src/privacy/audit.rs`
- **Root Cause:** Synthetic buffer & `:1080` probe checks don't expose real-world limits (ISP UDP DNS for non-proxy apps, direct browser WebRTC UDP, passthrough JA3).
- **Planned Fix:** Make check titles, summaries, proofs, and scoring honest and transparent (testing DoH/ODoH IPv4+IPv6 resolution, OS DNS warning visibility, honest SNI/JA3 scope, proxy WebRTC scope, and clean `ClientHello` buffer reassembly).

### BUG-10 to BUG-18 — Resolution & Live Verification Record

- **BUG-01 (`[x]`):** Added `camera_active`, `mic_active`, `camera_apps`, `mic_apps`, and `odoh_fallback_active` to `PrivacyMetrics` (`src-tauri/src/state.rs`); converted `AppState::get_metrics` / `get_privacy_metrics` (`lib.rs`) to `async fn`. Verified via `cargo test` (`test_hardware_probe_runs_safely_without_panic`) & `svelte-check` (0 errors).
- **BUG-02 (`[~]`):** `DohPool::resolve_ips_verified` queries `TYPE::A` with `TYPE::AAAA` fallback inside ODoH/DoH; `connect_with_doh` tries up to 4 resolved IPs with 5s timeouts and blocks plaintext OS `getaddrinfo()` fallback for non-local domains when privacy DNS is enabled. Transparently documented in UI & Security Check that non-proxy CLI/UDP apps use macOS DNS without a privileged root/TUN extension.
- **BUG-03 (`[~]`):** Decoupled `sni_fragmentation` from `ja3_shuffle` in `src-tauri/src/proxy/mod.rs` (`use_record_split = false`, gated solely on `sni_fragmentation`). Updated UI card (`Harden HTTP Headers & DoH Signatures`) and `audit.rs` Check 4 honestly: internal ODoH/DoH/chaff cipher shuffling + plain-HTTP header scrubbing apply, while browser HTTPS TLS passthrough leaves browser ciphers intact.
- **BUG-04 (`[~]`):** Expanded `STUN_TURN_DOMAINS` (`global.turn.twilio.com`, `turn.twilio.com`, `relay.twilio.com`, `xirsys.com`, `turn.xirsys.com`) and patterns (`stun0`, `turn0`, `turnserver`, `stunserver`) in `webrtc_shield.rs`. Verified live: `CONNECT global.turn.twilio.com:3478`, `turn0.example.org:443`, and `stun.l.google.com:19302` all returned `HTTP/1.1 403 Forbidden`. UI & Check 3 advise disabling non-proxied UDP in browsers for full defense.
- **BUG-05 (`[~]`):** `forward_tls_initial_flight()` now buffers split TLS `ClientHello` fragments up to 16 KB / 60 ms (`tls_len = 5 + record_len`). Verified live: 2-write split 1548-byte `ClientHello` to `example.com:443` received a valid 4096-byte TLS `ServerHello`. UI/Check 4 copy clarifies protection targets stateless single-packet DPI.
- **BUG-06 (`[x]`):** Added `strip_proxy_request_target` and `rewrite_http_proxy_head` in `fingerprint.rs`, and terminated HTTP tunnels immediately upon `target_to_client` completion in `proxy/mod.rs`. Verified live: mock server saw `GET /hello?x=1 HTTP/1.1`, `Proxy-Connection: False`, `X-Forwarded-For: False`, `Via: False`, `Connection: close: True`, and 2nd keep-alive `doubleclick.net` request hit immediate EOF (`smuggle_eof=True`).
- **BUG-07 (`[x]`):** Replaced blocking `client_stream.read()` with `tokio::select!` racing client vs server read in `forward_tls_initial_flight()`. Verified live against banner-first mock SMTP server over SOCKS5: received `220 mock-smtp.local ESMTP Ready` and `221 Bye` with zero deadlock.
- **BUG-08 (`[x]`):** Updated `dns/mod.rs` so `dns_enabled == false` skips ad/CNAME blocking without blackholing UDP `:5300` lookups; separated `odoh_dns_resolution` scoring from `dns_enabled` in `audit.rs`. Verified live UDP `:5300`: `dig example.com` returned `104.20.23.154` & `172.66.147.243`; `dig doubleclick.net` returned `0.0.0.0`.
- **BUG-09 (`[x]`):** Rewrote `audit.rs` Checks 1-4 for transparent scope (noting CLI/UDP DNS outside `:1080`, browser non-proxied UDP setting, passthrough browser HTTPS TLS vs internal DoH/HTTP hardening, and updating `odoh_fallback_active`).
- **BUG-10 (`[x]`):** Added bracketed IPv6 `parse_host_port` (`proxy/mod.rs`) with unit test `test_parse_host_port_ipv4_ipv6_and_domains` and verified live: `CONNECT [::1]:<port>` returned `HTTP/1.1 200 Connection Established` and echoed `V6_ECHO:PING6`.
- **BUG-11 (`[x]`):** Added `graceful_signal_shutdown` in `lib.rs` (awaited `spawn_blocking(disable_system_proxy)`, `app.exit(0)`, 250 ms `std::process::exit(0)` fallback) and non-blocking `quit_app` task in `tray.rs`. Verified live: `SIGTERM` exited cleanly in `4389 ms` (no hang or `SIGKILL`), logging `Reset OS proxy to direct connection on exit.` and restoring `Wi-Fi` proxy to `Enabled: No`.
- **BUG-12 (`[~]`):** Updated `trigger_manual_chaff_burst` (`lib.rs`) to return `Ok(false)` when `chaff_enabled` is false, `tray.rs` `"decoy_burst"` to log `CHAFF_SKIPPED`, and `+page.svelte` to disable `"Send Decoy Noise"` (`"Decoy Mode Off"`) cleanly. (`Ghost`/`Smokescreen` remain DNS-only decoy modes to conserve bandwidth.)
- **BUG-13 (`[x]`):** Updated `query_odoh` (`odoh.rs`) to iterate all `ODOH_ROUTES`, tracked `odoh_fallback_active` in `AppState`, and surfaced fallback status in Overview and tray tooltips.
- **BUG-14 (`[~]`):** Updated `clipboard.rs` to strip tracking tokens (`igsh`, `srsltid`, `gad_source`, `gad_campaignid`, `mc_cid`, `_gl`, `epik`, `sccid`, `s_kwcid`, `fb_action_ids`, `fb_action_types`), call `parsed.set_query(None)`, and preserve trailing sentence punctuation (`test_url_sanitization` & `test_text_with_embedded_url` pass). Plaintext clipboard write remains per `arboard`.
- **BUG-15 (`[x]`):** Updated `pii_redactor.rs` to run sequential `redact_pass` loops over the updated redacted string and reuse tokens on duplicate secrets (`test_no_overlap_between_api_keys_and_phones_and_duplicates_reused` passes).
- **BUG-16 (`[x]`):** Probed `AppleH13..H16CamIn` (`hardware_sentinel.rs`); added `state.proxy_enabled.store(false, ...)` + tray sync + `privacy-state-changed` emit on Panic (`panic.rs`, `lib.rs`, `tray.rs`); dynamic tooltip sync (`tray.rs`); fixed `RunEvent::Reopen` window check (`lib.rs`).
- **BUG-17 (`[x]`):** Deduplicated static rules via `UNIQUE_STATIC_RULE_COUNT` (`sinkhole.rs`) and expanded `PROXY_BYPASS_DOMAINS` with `172.16.0.0/12` & `169.254.0.0/16` (`sys_proxy.rs`), verified live via `networksetup -getproxybypassdomains "Wi-Fi"`.
- **BUG-18 (`[x]`):** Fixed missing `PacketFlag::RECURSION_DESIRED` (`RD=1`) in `doh_pool.rs`, `burst_trigger.rs`, and `test_all.rs`, added `validate_dns_reply()` + DoH multi-resolver fallback across `RESOLVERS`, and logged proxy `502` upstream errors to stderr. Verified live against `/Applications/Ephemeral Privacy.app`: 6 consecutive fetches to `https://globalnews.ca/bc/weather/CAXX0518/` and `https://example.com/` (3 rounds each, plus 12/12 in debug) all returned HTTP `200`.

### Final Verification Summary (Post-Final-Edit)
- `cargo test --manifest-path src-tauri/Cargo.toml`: **17 passed, 0 failed**
- `npm run check` (`svelte-check`): **0 errors, 0 warnings**
- `impeccable detect --json src/routes/+page.svelte src/app.css`: `[]`
- Release app (`/Applications/Ephemeral Privacy.app`) live suite: all IPv6 CONNECT, Banner-First SOCKS5, HTTP Keep-Alive smuggling/header rewrite, 2-write split `ClientHello`, tracker/WebRTC `403` blocks, UDP `:5300` DNS, 3x2 HTTPS `200` fetches, and `SIGTERM` clean proxy teardown checks passed.
