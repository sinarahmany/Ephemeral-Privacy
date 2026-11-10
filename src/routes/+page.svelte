<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import {
    Shield,
    ShieldAlert,
    ShieldCheck,
    Activity,
    Flame,
    EyeOff,
    Radio,
    Lock,
    RefreshCw,
    Sliders,
    Terminal,
    AlertTriangle,
    Copy,
    CheckCircle,
    Zap,
    ExternalLink,
    Filter,
    Layers,
    Send
  } from "@lucide/svelte";

  // Reactive state using Svelte 5 runes
  let activeTab = $state<"dashboard" | "modules" | "ai_sandbox" | "url_cleaner" | "os_telemetry">("dashboard");

  let status = $state({
    proxy_enabled: true,
    dns_enabled: true,
    chaff_enabled: true,
    sni_fragmentation: true,
    clipboard_cleaner: true,
    pii_redactor: true,
    chaff_intensity: "Smokescreen",
    upstream_resolver: "Rotated (Quad9, Mullvad, Cloudflare)",
  });

  let metrics = $state({
    queries_intercepted: 0,
    chaff_queries_sent: 0,
    trackers_blocked: 0,
    pii_sanitized: 0,
    sni_sliced_handshakes: 0,
  });

  interface PrivacyEvent {
    id: number;
    timestamp: number;
    category: string;
    title: string;
    details: string;
    target: string;
  }

  let recentEvents = $state<PrivacyEvent[]>([]);
  let isPanicLoading = $state(false);
  let panicMessage = $state("");

  // Sandbox states
  let sandboxInput = $state(
    "Please review this code for user alex.morgan@fintech.io. Authorization: Bearer sk-ant-api03-9999888877776666555544443333222211110000. Customer card on file is 4532 0151 1283 0366."
  );
  let sandboxResult = $state<{
    sanitized_text: string;
    redactions_count: number;
    token_map: Record<string, string>;
  } | null>(null);
  let sandboxRestored = $state("");

  // URL Cleaner test state
  let testUrlInput = $state(
    "https://store.example.com/item/4829?utm_source=facebook&utm_medium=cpc&utm_campaign=winter_sale&fbclid=IwAR29184712048124&gclid=Cj0KCQjwgJ8&ref_src=twsrc"
  );
  let testUrlCleaned = $state<string | null>(null);

  // OS Telemetry items
  interface OsItem {
    id: string;
    name: string;
    os: string;
    description: string;
    risk_level: string;
  }
  let telemetryList = $state<OsItem[]>([]);

  async function fetchStatus() {
    try {
      status = await invoke("get_privacy_status");
      metrics = await invoke("get_privacy_metrics");
      recentEvents = await invoke("get_recent_events");
    } catch (e) {
      console.error("Failed fetching privacy status:", e);
    }
  }

  async function handleToggle(feature: string, current: boolean) {
    try {
      await invoke("toggle_feature", { feature, enabled: !current });
      await fetchStatus();
    } catch (e) {
      console.error(`Toggle error for ${feature}:`, e);
    }
  }

  async function handleIntensityChange(intensity: string) {
    try {
      await invoke("set_chaff_intensity", { intensity });
      await fetchStatus();
    } catch (e) {
      console.error("Failed setting intensity:", e);
    }
  }

  async function triggerManualBurst() {
    try {
      await invoke("trigger_manual_chaff_burst");
      await fetchStatus();
    } catch (e) {
      console.error("Manual burst error:", e);
    }
  }

  async function handlePanic() {
    if (!confirm("EMERGENCY PANIC: Restore direct network connection, flush system DNS cache, and purge clipboard?")) {
      return;
    }
    isPanicLoading = true;
    try {
      panicMessage = await invoke("trigger_panic");
      await fetchStatus();
    } catch (e) {
      panicMessage = `Panic failed: ${e}`;
    } finally {
      isPanicLoading = false;
      setTimeout(() => {
        panicMessage = "";
      }, 5000);
    }
  }

  async function runSandboxRedact() {
    try {
      sandboxResult = await invoke("redact_pii_prompt", { prompt: sandboxInput });
      sandboxRestored = "";
    } catch (e) {
      console.error("Sandbox redact error:", e);
    }
  }

  async function runSandboxRestore() {
    if (!sandboxResult) return;
    try {
      sandboxRestored = await invoke("restore_pii_prompt", {
        prompt: sandboxResult.sanitized_text,
        tokenMap: sandboxResult.token_map,
      });
    } catch (e) {
      console.error("Sandbox restore error:", e);
    }
  }

  async function runUrlCleaner() {
    try {
      testUrlCleaned = await invoke("sanitize_url_input", { raw: testUrlInput });
    } catch (e) {
      console.error("URL cleaner error:", e);
    }
  }

  async function loadTelemetry() {
    try {
      telemetryList = await invoke("get_os_telemetry_list");
    } catch (e) {
      console.error("Failed loading telemetry list:", e);
    }
  }

  onMount(() => {
    fetchStatus();
    runSandboxRedact();
    runUrlCleaner();
    loadTelemetry();

    // Auto-refresh metrics every 1.5 seconds
    const interval = setInterval(fetchStatus, 1500);
    return () => clearInterval(interval);
  });
</script>

<div class="h-screen w-screen flex flex-col bg-[#0b0f19] text-slate-100 antialiased overflow-hidden select-none">
  <!-- TOP APP HEADER -->
  <header class="h-16 border-b border-slate-800/80 bg-slate-950/70 px-6 flex items-center justify-between shrink-0 backdrop-blur-md">
    <div class="flex items-center gap-3">
      <div class="h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-indigo-500/20 ring-1 ring-white/20">
        <ShieldCheck class="w-6 h-6 text-white" />
      </div>
      <div>
        <div class="flex items-center gap-2">
          <span class="font-bold tracking-wider text-sm text-slate-100">EPHEMERAL</span>
          <span class="text-xs px-1.5 py-0.5 rounded font-mono font-semibold bg-cyan-950 text-cyan-400 border border-cyan-800/50">PRIVACY SUITE</span>
        </div>
        <div class="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5">
          <span class="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>Shields Active</span>
          <span class="text-slate-600">•</span>
          <span class="font-mono text-slate-300">Proxy :1080</span>
          <span class="text-slate-600">•</span>
          <span class="font-mono text-slate-300">DNS :5353</span>
        </div>
      </div>
    </div>

    <!-- HEADER RIGHT CONTROLS -->
    <div class="flex items-center gap-3">
      {#if panicMessage}
        <div class="text-xs px-3 py-1.5 rounded-lg bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 font-mono animate-fade-in">
          {panicMessage}
        </div>
      {/if}

      <button
        onclick={triggerManualBurst}
        class="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 border border-slate-700 text-xs font-medium text-slate-200 transition-colors shadow-sm"
        title="Fire synthetic decoy queries across multiple DoH resolvers now"
      >
        <Radio class="w-3.5 h-3.5 text-cyan-400" />
        Emit Chaff Burst
      </button>

      <button
        onclick={handlePanic}
        disabled={isPanicLoading}
        class="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-red-950/80 hover:bg-red-900 border border-red-700/80 text-xs font-semibold text-red-200 transition-all shadow-lg shadow-red-950/40 hover:scale-[1.02] active:scale-[0.98]"
      >
        <Flame class="w-3.5 h-3.5 text-red-400 animate-pulse" />
        PANIC KILL-SWITCH
      </button>
    </div>
  </header>

  <!-- METRICS STRIP -->
  <div class="grid grid-cols-4 gap-4 px-6 py-4 bg-slate-900/40 border-b border-slate-800/60 shrink-0">
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm">
      <div>
        <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Queries Protected</div>
        <div class="text-2xl font-bold font-mono text-slate-100 mt-1">{metrics.queries_intercepted}</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
        <Activity class="w-5 h-5" />
      </div>
    </div>

    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm">
      <div>
        <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Chaff Decoys Emitted</div>
        <div class="text-2xl font-bold font-mono text-cyan-400 mt-1">{metrics.chaff_queries_sent}</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
        <Radio class="w-5 h-5 animate-pulse" />
      </div>
    </div>

    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm">
      <div>
        <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Trackers Sinkholed</div>
        <div class="text-2xl font-bold font-mono text-amber-400 mt-1">{metrics.trackers_blocked}</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
        <EyeOff class="w-5 h-5" />
      </div>
    </div>

    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm">
      <div>
        <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">SNI DPI Slices</div>
        <div class="text-2xl font-bold font-mono text-emerald-400 mt-1">{metrics.sni_sliced_handshakes}</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
        <Lock class="w-5 h-5" />
      </div>
    </div>
  </div>

  <!-- NAVIGATION TABS -->
  <div class="px-6 border-b border-slate-800/80 bg-slate-950/40 flex gap-2 shrink-0">
    <button
      onclick={() => (activeTab = "dashboard")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'dashboard' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Activity class="w-4 h-4" />
      Chaff Radar & Live Stream
    </button>
    <button
      onclick={() => (activeTab = "modules")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'modules' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Sliders class="w-4 h-4" />
      Privacy Shields & Controls
    </button>
    <button
      onclick={() => (activeTab = "ai_sandbox")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'ai_sandbox' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Lock class="w-4 h-4" />
      AI & Chat PII Sanitizer
    </button>
    <button
      onclick={() => (activeTab = "url_cleaner")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'url_cleaner' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Filter class="w-4 h-4" />
      Link De-tracker
    </button>
    <button
      onclick={() => (activeTab = "os_telemetry")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'os_telemetry' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Layers class="w-4 h-4" />
      OS Telemetry Profiles
    </button>
  </div>

  <!-- MAIN TAB CONTENT -->
  <main class="flex-1 overflow-y-auto p-6">
    {#if activeTab === "dashboard"}
      <div class="grid grid-cols-12 gap-6 h-full">
        <!-- LEFT: CHAFF RADAR & CONFIG -->
        <div class="col-span-5 flex flex-col gap-6">
          <!-- Chaff Visualizer Card -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
            <div class="flex items-center justify-between mb-4">
              <div>
                <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Radio class="w-4 h-4 text-cyan-400 animate-pulse" />
                  Query De-correlation Engine
                </h3>
                <p class="text-xs text-slate-400 mt-0.5">Poisson Burst Generator & Multi-DoH Dispersion</p>
              </div>
              <span class="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                ACTIVE
              </span>
            </div>

            <!-- Radar Animated Wave Canvas Simulation -->
            <div class="h-36 rounded-xl bg-slate-950/80 border border-slate-800/80 relative flex items-center justify-center overflow-hidden">
              <div class="absolute inset-0 bg-[radial-gradient(#06b6d4_1px,transparent_1px)] [background-size:16px_16px] opacity-20"></div>
              
              <!-- Expanding concentric rings -->
              <div class="absolute w-24 h-24 rounded-full border border-cyan-500/30 animate-ping"></div>
              <div class="absolute w-16 h-16 rounded-full border border-cyan-400/50"></div>
              <div class="absolute w-6 h-6 rounded-full bg-cyan-400/80 shadow-lg shadow-cyan-400/50 flex items-center justify-center">
                <span class="w-2 h-2 rounded-full bg-white"></span>
              </div>

              <!-- Rotating scan line -->
              <div class="absolute w-28 h-28 border-r border-cyan-400/40 rounded-full animate-spin [animation-duration:3s]"></div>

              <div class="absolute bottom-2 left-3 text-[10px] font-mono text-cyan-400/80">
                DISPERSION: QUAD9 ↔ MULLVAD ↔ CLOUDFLARE
              </div>
            </div>

            <!-- Chaff Intensity Selector -->
            <div class="mt-4">
              <label class="text-xs font-medium text-slate-300 block mb-2">Chaff Smokescreen Density</label>
              <div class="grid grid-cols-3 gap-2">
                {#each ["Ghost", "Smokescreen", "HeavyFog"] as mode}
                  <button
                    onclick={() => handleIntensityChange(mode)}
                    class="px-2.5 py-1.5 rounded-lg text-xs font-medium border transition-all text-center {status.chaff_intensity === mode ? 'bg-cyan-500/20 border-cyan-500 text-cyan-200' : 'bg-slate-800/40 border-slate-700/60 text-slate-400 hover:text-slate-200'}"
                  >
                    {mode}
                  </button>
                {/each}
              </div>
            </div>
          </div>

          <!-- Anti-DPI & SNI Slicing Status Card -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-2">
              <Lock class="w-4 h-4 text-emerald-400" />
              Anti-ISP Deep Packet Inspection (DPI)
            </h3>
            <p class="text-xs text-slate-400 leading-relaxed">
              Splits the unencrypted TLS 1.3 <span class="font-mono text-cyan-300">ClientHello</span> packet right through the middle of the SNI domain name. ISP line-rate DPI middleboxes cannot extract the hostname, keeping your visited domains invisible.
            </p>
            <div class="mt-3 flex items-center justify-between text-xs bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
              <span class="text-slate-300">SNI TCP Slicing</span>
              <span class="font-mono text-emerald-400 font-semibold">{status.sni_fragmentation ? "ENABLED" : "DISABLED"}</span>
            </div>
          </div>
        </div>

        <!-- RIGHT: LIVE MEMORY-ONLY PRIVACY STREAM -->
        <div class="col-span-7 bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col">
          <div class="flex items-center justify-between mb-3 shrink-0">
            <div>
              <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
                <Terminal class="w-4 h-4 text-cyan-400" />
                Live Privacy Event Stream
              </h3>
              <p class="text-[11px] text-slate-400">Zero disk persistence. All entries exist purely in volatile RAM.</p>
            </div>
            <span class="text-[10px] font-mono text-slate-500">MAX 50 EVENTS</span>
          </div>

          <!-- Log stream list -->
          <div class="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[300px] max-h-[460px]">
            {#if recentEvents.length === 0}
              <div class="h-48 flex flex-col items-center justify-center text-slate-500 text-xs">
                <Shield class="w-8 h-8 mb-2 opacity-30" />
                No events recorded yet. Browse or emit a chaff burst to see live activity.
              </div>
            {:else}
              {#each recentEvents as ev (ev.id)}
                <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3 text-xs flex flex-col gap-1 transition-all hover:border-slate-700">
                  <div class="flex items-center justify-between">
                    <span class="font-medium text-slate-200 flex items-center gap-2">
                      {#if ev.category === "DNS_CHAFF" || ev.category === "SEARCH_CHAFF"}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/50">CHAFF</span>
                      {:else if ev.category === "TRACKER_BLOCKED"}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800/50">SINKHOLE</span>
                      {:else if ev.category === "SNI_FRAGMENTED"}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/50">ANTI-DPI</span>
                      {:else if ev.category === "URL_SANITIZED"}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-400 border border-indigo-800/50">CLEANED</span>
                      {:else}
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">SYSTEM</span>
                      {/if}
                      {ev.title}
                    </span>
                    <span class="text-[10px] font-mono text-slate-500">{new Date(ev.timestamp * 1000).toLocaleTimeString()}</span>
                  </div>
                  <div class="text-slate-400 text-[11px] leading-relaxed">{ev.details}</div>
                  <div class="text-[10px] font-mono text-cyan-500/80 truncate">Target: {ev.target}</div>
                </div>
              {/each}
            {/if}
          </div>
        </div>
      </div>
    {:else if activeTab === "modules"}
      <!-- PRIVACY SHIELDS & CONTROLS -->
      <div class="max-w-4xl mx-auto space-y-4">
        <div>
          <h2 class="text-base font-bold text-slate-100">Privacy Module Controls</h2>
          <p class="text-xs text-slate-400">Configure background shields, upstream resolvers, and interception rules.</p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Module 1: Query De-correlator -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <Radio class="w-4 h-4 text-cyan-400" />
                <span class="text-sm font-semibold text-slate-200">Ephemeral Query De-correlator</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Intersperses realistic decoy DNS & search queries with Poisson-jittered delays across multiple upstreams to break ISP/profiler correlation.
              </p>
            </div>
            <button
              aria-label="Toggle Ephemeral Query De-correlator"
              onclick={() => handleToggle("chaff", status.chaff_enabled)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.chaff_enabled ? 'bg-cyan-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.chaff_enabled ? 'translate-x-6' : ''}"></span>
            </button>
          </div>

          <!-- Module 2: Anti-DPI SNI Fragmentation -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <Lock class="w-4 h-4 text-emerald-400" />
                <span class="text-sm font-semibold text-slate-200">Anti-DPI SNI Fragmentation</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Slices TLS ClientHello packets across TCP boundaries so ISP Deep Packet Inspection boxes cannot see which HTTPS websites you connect to.
              </p>
            </div>
            <button
              aria-label="Toggle Anti-DPI SNI Fragmentation"
              onclick={() => handleToggle("sni", status.sni_fragmentation)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.sni_fragmentation ? 'bg-emerald-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.sni_fragmentation ? 'translate-x-6' : ''}"></span>
            </button>
          </div>

          <!-- Module 3: Local DNS Sinkhole & CNAME Uncloaking -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <EyeOff class="w-4 h-4 text-amber-400" />
                <span class="text-sm font-semibold text-slate-200">DNS Sinkhole & CNAME Uncloaker</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Sinkholes ad/tracking servers system-wide on 127.0.0.1:5353. Unmasks first-party CNAME cloaking used to evade traditional ad-blockers.
              </p>
            </div>
            <button
              aria-label="Toggle DNS Sinkhole"
              onclick={() => handleToggle("dns", status.dns_enabled)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.dns_enabled ? 'bg-amber-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.dns_enabled ? 'translate-x-6' : ''}"></span>
            </button>
          </div>

          <!-- Module 4: Clipboard Sanitizer -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <Filter class="w-4 h-4 text-indigo-400" />
                <span class="text-sm font-semibold text-slate-200">Universal Clipboard Link Cleaner</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Monitors system clipboard and strips 250+ tracking tokens (fbclid, gclid, utm_*) in &lt;1ms without breaking destinations.
              </p>
            </div>
            <button
              aria-label="Toggle Clipboard Sanitizer"
              onclick={() => handleToggle("clipboard", status.clipboard_cleaner)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.clipboard_cleaner ? 'bg-indigo-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.clipboard_cleaner ? 'translate-x-6' : ''}"></span>
            </button>
          </div>

          <!-- Module 5: OS System Proxy Integration -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <Activity class="w-4 h-4 text-blue-400" />
                <span class="text-sm font-semibold text-slate-200">System Proxy Auto-Routing</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Applies system-wide HTTP & SOCKS5 proxy settings to 127.0.0.1:1080 without requiring root/sudo privileges.
              </p>
            </div>
            <button
              aria-label="Toggle System Proxy"
              onclick={() => handleToggle("proxy", status.proxy_enabled)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.proxy_enabled ? 'bg-blue-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.proxy_enabled ? 'translate-x-6' : ''}"></span>
            </button>
          </div>

          <!-- Module 6: PII & Secret Redactor -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
            <div class="space-y-1 pr-4">
              <div class="flex items-center gap-2">
                <ShieldCheck class="w-4 h-4 text-cyan-400" />
                <span class="text-sm font-semibold text-slate-200">Chat & LLM PII Masker</span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Automatically masks credit cards (Luhn validated), emails, phone numbers, and API keys before sending to AI or web chats.
              </p>
            </div>
            <button
              aria-label="Toggle Chat PII Masker"
              onclick={() => handleToggle("pii", status.pii_redactor)}
              class="w-12 h-6 rounded-full transition-colors relative shrink-0 {status.pii_redactor ? 'bg-cyan-500' : 'bg-slate-700'}"
            >
              <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.pii_redactor ? 'translate-x-6' : ''}"></span>
            </button>
          </div>
        </div>
      </div>
    {:else if activeTab === "ai_sandbox"}
      <!-- AI & CHAT SANITIZER PLAYGROUND -->
      <div class="max-w-4xl mx-auto space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <Lock class="w-5 h-5 text-cyan-400" />
            AI & Web Chat Data Privacy Sandbox
          </h2>
          <p class="text-xs text-slate-400">
            Paste any sensitive prompt below to test zero-latency local pseudonymization and bidirectional de-tokenization.
          </p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Input Box -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col">
            <label class="text-xs font-semibold text-slate-300 mb-2">Original Prompt (Before Sending to AI)</label>
            <textarea
              bind:value={sandboxInput}
              class="flex-1 w-full bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 resize-none focus:outline-none focus:border-cyan-500 min-h-[160px]"
            ></textarea>
            <button
              onclick={runSandboxRedact}
              class="mt-3 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition-colors flex items-center justify-center gap-2"
            >
              <Zap class="w-3.5 h-3.5" />
              Redact PII & Secrets
            </button>
          </div>

          <!-- Output Box -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col">
            <div class="flex items-center justify-between mb-2">
              <label class="text-xs font-semibold text-cyan-300">Sanitized Prompt (What the LLM Sees)</label>
              {#if sandboxResult}
                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                  {sandboxResult.redactions_count} Entities Masked
                </span>
              {/if}
            </div>
            <div class="flex-1 w-full bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 overflow-y-auto min-h-[160px] whitespace-pre-wrap">
              {sandboxResult?.sanitized_text || "Click 'Redact PII' to test..."}
            </div>
            <button
              onclick={runSandboxRestore}
              disabled={!sandboxResult}
              class="mt-3 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <RefreshCw class="w-3.5 h-3.5" />
              Test Local De-tokenization (Restore Original)
            </button>
          </div>
        </div>

        {#if sandboxResult && Object.keys(sandboxResult.token_map).length > 0}
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <h4 class="text-xs font-semibold text-slate-300 mb-2">In-Memory Pseudonymization Map (Strictly Local)</h4>
            <div class="grid grid-cols-2 gap-2">
              {#each Object.entries(sandboxResult.token_map) as [token, orig]}
                <div class="bg-slate-950/80 border border-slate-800 rounded-lg p-2 text-xs font-mono flex items-center justify-between">
                  <span class="text-cyan-400">{token}</span>
                  <span class="text-slate-500 truncate max-w-[240px]">{orig}</span>
                </div>
              {/each}
            </div>
          </div>
        {/if}

        {#if sandboxRestored}
          <div class="bg-slate-900/60 border border-emerald-800/40 rounded-2xl p-4">
            <h4 class="text-xs font-semibold text-emerald-400 mb-1 flex items-center gap-1.5">
              <CheckCircle class="w-4 h-4" />
              Restored Prompt
            </h4>
            <p class="text-xs font-mono text-slate-200">{sandboxRestored}</p>
          </div>
        {/if}
      </div>
    {:else if activeTab === "url_cleaner"}
      <!-- LINK DE-TRACKER TOOL -->
      <div class="max-w-3xl mx-auto space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <Filter class="w-5 h-5 text-indigo-400" />
            Universal Link De-tracker
          </h2>
          <p class="text-xs text-slate-400">
            This module automatically runs in the background for your system clipboard. Test any URL below to see how tracking parameters are eradicated.
          </p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-lg">
          <div>
            <label class="text-xs font-medium text-slate-300 block mb-1.5">Input URL with Tracking Parameters</label>
            <input
              type="text"
              bind:value={testUrlInput}
              class="w-full bg-slate-950/80 border border-slate-800 rounded-xl px-3.5 py-2.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
            />
          </div>

          <button
            onclick={runUrlCleaner}
            class="px-4 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-xs font-semibold text-white transition-colors flex items-center gap-2"
          >
            <Filter class="w-3.5 h-3.5" />
            Clean Tracking Tokens
          </button>

          {#if testUrlCleaned}
            <div class="pt-2 border-t border-slate-800/80">
              <div class="text-xs font-semibold text-indigo-300 mb-1 flex items-center gap-1.5">
                <CheckCircle class="w-4 h-4 text-emerald-400" />
                Sanitized URL Result:
              </div>
              <div class="bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 break-all select-all">
                {testUrlCleaned}
              </div>
            </div>
          {/if}
        </div>
      </div>
    {:else if activeTab === "os_telemetry"}
      <!-- OS TELEMETRY PROFILES -->
      <div class="max-w-3xl mx-auto space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <Layers class="w-5 h-5 text-cyan-400" />
            Cross-Platform OS Telemetry Silencer
          </h2>
          <p class="text-xs text-slate-400">
            Operating systems continuously phone home with diagnostic telemetry and machine identifiers. Below are the monitored profiles handled by the local DNS sinkhole.
          </p>
        </div>

        <div class="space-y-3">
          {#each telemetryList as item}
            <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex items-start justify-between">
              <div class="space-y-1">
                <div class="flex items-center gap-2">
                  <span class="text-xs font-mono px-2 py-0.5 rounded uppercase font-semibold bg-slate-800 text-slate-300">
                    {item.os}
                  </span>
                  <span class="text-sm font-semibold text-slate-200">{item.name}</span>
                </div>
                <p class="text-xs text-slate-400 leading-relaxed">{item.description}</p>
              </div>
              <span class="text-[10px] font-mono px-2 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 shrink-0">
                SINKHOLED
              </span>
            </div>
          {/each}
        </div>
      </div>
    {/if}
  </main>

  <!-- BOTTOM STATUS BAR -->
  <footer class="h-8 border-t border-slate-800/80 bg-slate-950 px-6 flex items-center justify-between text-[11px] text-slate-500 shrink-0 font-mono">
    <div class="flex items-center gap-3">
      <span>UPSTREAM: {status.upstream_resolver}</span>
      <span>•</span>
      <span>CHAFF: {status.chaff_intensity}</span>
    </div>
    <div>ZERO-KNOWLEDGE RAM ARCHITECTURE • NO DISK LOGS</div>
  </footer>
</div>
