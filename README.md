# Ephemeral Privacy Suite

A modern, lightweight, cross-platform privacy and anti-surveillance desktop application and background daemon built with **Rust & Tauri v2** and **Svelte 5**.

Targeting macOS, Linux, and Windows, it directly addresses surveillance capitalism, ISP Deep Packet Inspection (DPI), DNS correlation, search profiling, and AI/chat data harvesting.

---

## Key Privacy Modules

### 1. Ephemeral Query De-correlator (Search & DNS Chaff Engine)
- **Event-Driven Chaff Triggering:** Intercepts real queries as you browse and emits a burst of 2–7 realistic decoy queries with Poisson micro-delays (250ms–3500ms).
- **Multi-Upstream Dispersion:** Decoys are rotated across disparate encrypted DoH resolvers (**Quad9, Mullvad, Cloudflare, LibreDNS**) with random TTL offsets.
- **Plausible Search Grammar:** Employs organic topics (science, engineering, history, technology) sent to alternative privacy engines (DuckDuckGo, Brave Search, Startpage) with human browser headers.
- **Adjustable Smokescreen Intensity:** `Ghost` (light), `Smokescreen` (standard), or `HeavyFog` (maximum noise).

### 2. Anti-ISP & Anti-DPI Shield (TLS SNI Fragmentation)
- Slices the TLS 1.3 `ClientHello` TCP packet right through the middle of the unencrypted Server Name Indication (SNI) domain name.
- Blinds ISP Deep Packet Inspection (DPI) middleboxes that attempt to log every visited website, while web servers reassemble the TCP stream normally.

### 3. Local DNS Sinkhole & CNAME Uncloaking
- High-throughput DNS resolver on `127.0.0.1:5353`.
- Sinkholes ad and telemetry domains across all desktop applications (Discord, Spotify, Electron apps, games).
- **CNAME Uncloaking:** Unmasks third-party trackers hiding behind first-party subdomains.

### 4. AI & Web Chat Privacy Guard (Reversible PII Masking)
- Intercepts sensitive prompts before they leave the machine for web chats (ChatGPT, Claude, Gemini).
- Zero-latency detection of emails, phone numbers, API keys (OpenAI `sk-...`, AWS `AKIA...`, GitHub tokens), and credit cards (validated with the **Luhn algorithm**).
- **Reversible Tokenization:** Stores an in-memory dictionary to de-tokenize model responses locally.

### 5. Universal Link De-tracker & Clipboard Sanitizer
- Background clipboard daemon that monitors copied URLs and removes 250+ tracking parameters (`fbclid`, `gclid`, `utm_*`, `msclkid`, etc.) in `<1` ms.

### 6. Zero-Knowledge RAM-Only Architecture & Emergency Panic Switch
- Visited domains, DNS requests, and decoy streams are never written to disk (strictly kept in a volatile ring buffer in RAM).
- Instant Panic Button restores direct network routing and flushes OS DNS caches.

---

## Development & Usage

### Prerequisites
- [Rust](https://rustup.rs/) (1.80+)
- [Node.js](https://nodejs.org/) (20+)

### Commands
```bash
# Install frontend dependencies
npm install

# Run automated tests
cd src-tauri && cargo test && cd ..

# Run in desktop development mode (with hot-reloading)
npm run tauri dev

# Build production bundle
npm run tauri build
```
