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
    Send,
    Info,
    ChevronDown,
    ChevronUp
  } from "@lucide/svelte";

  // Navigation tab state
  let activeTab = $state<"dashboard" | "modules" | "ai_sandbox" | "url_cleaner" | "os_telemetry">("dashboard");

  // First-time user guide toggle
  let showFirstTimeGuide = $state(true);

  // Active info tooltip popup
  let activeInfoModal = $state<string | null>(null);

  let status = $state({
    proxy_enabled: true,
    dns_enabled: true,
    chaff_enabled: true,
    sni_fragmentation: true,
    clipboard_cleaner: true,
    pii_redactor: true,
    chaff_intensity: "Smokescreen",
    upstream_resolver: "Rotated (Quad9, Mullvad, Cloudflare)",
    os_proxy_active: true,
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

  // AI Sandbox states
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

  async function handleReassertProxy() {
    try {
      await invoke("reassert_system_proxy");
      await fetchStatus();
    } catch (e) {
      console.error("Failed to re-assert system proxy:", e);
    }
  }

  async function handlePanic() {
    if (!confirm("EMERGENCY RESET: Restore direct network connection, flush system DNS cache, and purge clipboard?")) {
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
          <span class="font-mono text-cyan-400">Encrypted DoH</span>
          
          {#if !status.os_proxy_active}
            <button
              onclick={handleReassertProxy}
              class="ml-2 px-2 py-0.5 rounded bg-amber-950/80 hover:bg-amber-900 border border-amber-600/80 text-[10px] text-amber-300 font-semibold flex items-center gap-1 transition-colors animate-pulse"
              title="Click to re-route your browser & OS traffic through the privacy proxy"
            >
              <AlertTriangle class="w-3 h-3 text-amber-400" />
              OS Proxy Inactive (Click to Re-enable)
            </button>
          {/if}
        </div>
      </div>
    </div>

    <!-- Quick Action Controls -->
    <div class="flex items-center gap-3">
      {#if panicMessage}
        <span class="text-xs font-mono text-emerald-400 bg-emerald-950/80 border border-emerald-800 px-3 py-1 rounded-lg">
          {panicMessage}
        </span>
      {/if}

      <button
        onclick={triggerManualBurst}
        class="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/80 text-xs font-medium text-cyan-300 transition-all shadow-sm hover:scale-[1.02] active:scale-[0.98]"
        title="Fire an instant burst of realistic camouflage queries across Quad9, Mullvad, and Cloudflare"
      >
        <Radio class="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
        Send Decoy Burst
      </button>

      <button
        onclick={handlePanic}
        disabled={isPanicLoading}
        class="flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-red-950/80 hover:bg-red-900 border border-red-700/80 text-xs font-semibold text-red-200 transition-all shadow-lg shadow-red-950/40 hover:scale-[1.02] active:scale-[0.98]"
        title="Emergency reset: restores direct connection, flushes system DNS, and purges clipboard"
      >
        <Flame class="w-3.5 h-3.5 text-red-400 animate-pulse" />
        EMERGENCY RESET
      </button>
    </div>
  </header>

  <!-- METRICS STRIP WITH FRIENDLY EXPLANATIONS -->
  <div class="grid grid-cols-4 gap-4 px-6 py-4 bg-slate-900/40 border-b border-slate-800/60 shrink-0">
    <!-- Metric 1: Web Requests Shielded -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm relative group">
      <div>
        <div class="flex items-center gap-1.5">
          <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Web Requests Shielded</div>
          <button 
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'queries' ? null : 'queries'} 
            class="text-slate-500 hover:text-cyan-400 transition-colors"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-2xl font-bold font-mono text-slate-100 mt-0.5">{metrics.queries_intercepted}</div>
        <div class="text-[10px] text-slate-500 mt-0.5">Sites routed through local shield</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
        <Activity class="w-5 h-5" />
      </div>
    </div>

    <!-- Metric 2: Camouflage Decoys Sent -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm relative group">
      <div>
        <div class="flex items-center gap-1.5">
          <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Camouflage Searches Sent</div>
          <button 
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'chaff' ? null : 'chaff'} 
            class="text-slate-500 hover:text-cyan-400 transition-colors"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-2xl font-bold font-mono text-cyan-400 mt-0.5">{metrics.chaff_queries_sent}</div>
        <div class="text-[10px] text-slate-500 mt-0.5">Decoys sent to poison ad profiles</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
        <Radio class="w-5 h-5 animate-pulse" />
      </div>
    </div>

    <!-- Metric 3: Trackers & Ads Blocked -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm relative group">
      <div>
        <div class="flex items-center gap-1.5">
          <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">Trackers & Ads Blocked</div>
          <button 
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'trackers' ? null : 'trackers'} 
            class="text-slate-500 hover:text-amber-400 transition-colors"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-2xl font-bold font-mono text-amber-400 mt-0.5">{metrics.trackers_blocked}</div>
        <div class="text-[10px] text-slate-500 mt-0.5">Ad networks & spyware dropped</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400">
        <EyeOff class="w-5 h-5" />
      </div>
    </div>

    <!-- Metric 4: Anti-ISP Handshake Slices -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 flex items-center justify-between shadow-sm relative group">
      <div>
        <div class="flex items-center gap-1.5">
          <div class="text-[11px] font-medium uppercase tracking-wider text-slate-400">ISP Snooping Blocks</div>
          <button 
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'sni' ? null : 'sni'} 
            class="text-slate-500 hover:text-emerald-400 transition-colors"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-2xl font-bold font-mono text-emerald-400 mt-0.5">{metrics.sni_sliced_handshakes}</div>
        <div class="text-[10px] text-slate-500 mt-0.5">Packets sliced to hide site names</div>
      </div>
      <div class="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400">
        <Lock class="w-5 h-5" />
      </div>
    </div>
  </div>

  <!-- EXPANDABLE EXPLANATION BANNER (If user clicked an info icon) -->
  {#if activeInfoModal}
    <div class="px-6 py-3 bg-slate-900/90 border-b border-cyan-800/40 text-xs flex items-center justify-between text-slate-200">
      <div class="flex items-center gap-2">
        <Info class="w-4 h-4 text-cyan-400 shrink-0" />
        {#if activeInfoModal === 'queries'}
          <span><strong>Web Requests Shielded:</strong> Count of actual website connections (via HTTP/HTTPS and SOCKS5) handled by your private local proxy daemon, protecting your true origin and resolving DNS via encrypted DoH.</span>
        {:else if activeInfoModal === 'chaff'}
          <span><strong>Camouflage Searches Sent:</strong> Synthetic, realistic search and DNS decoys fired across multiple resolvers (Quad9, Mullvad, Cloudflare) with randomized delays to make ad tracking mathematically impossible.</span>
        {:else if activeInfoModal === 'trackers'}
          <span><strong>Trackers & Ads Blocked:</strong> Known tracking brokers, telemetry endpoints, and sneaky disguised CNAME trackers that were dropped before they could collect data from your computer.</span>
        {:else if activeInfoModal === 'sni'}
          <span><strong>ISP Snooping Blocks:</strong> Slices the unencrypted Server Name Indication (SNI) in your HTTPS connection packets across TCP boundaries so your Internet Service Provider's deep packet inspection (DPI) boxes cannot read what website you are visiting.</span>
        {/if}
      </div>
      <button onclick={() => activeInfoModal = null} class="text-xs text-slate-400 hover:text-white px-2 py-0.5">Dismiss</button>
    </div>
  {/if}

  <!-- NAVIGATION TABS -->
  <div class="px-6 border-b border-slate-800/80 bg-slate-950/40 flex gap-2 shrink-0">
    <button
      onclick={() => (activeTab = "dashboard")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'dashboard' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Activity class="w-4 h-4" />
      Dashboard & Live Activity
    </button>
    <button
      onclick={() => (activeTab = "modules")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'modules' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Sliders class="w-4 h-4" />
      Shields & Anti-ISP Controls
    </button>
    <button
      onclick={() => (activeTab = "ai_sandbox")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'ai_sandbox' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Lock class="w-4 h-4" />
      AI & Chat Privacy Shield
    </button>
    <button
      onclick={() => (activeTab = "url_cleaner")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'url_cleaner' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Filter class="w-4 h-4" />
      Tracking Link Stripper
    </button>
    <button
      onclick={() => (activeTab = "os_telemetry")}
      class="px-4 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-2 {activeTab === 'os_telemetry' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Layers class="w-4 h-4" />
      System Telemetry Audit
    </button>
  </div>

  <!-- MAIN TAB CONTENT -->
  <main class="flex-1 overflow-y-auto p-6">
    {#if activeTab === "dashboard"}
      <div class="space-y-6">
        <!-- FIRST-TIME USER EXPLAINER BANNER -->
        {#if showFirstTimeGuide}
          <div class="bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-800/40 rounded-2xl p-4 shadow-lg relative">
            <div class="flex items-center justify-between mb-3">
              <div class="flex items-center gap-2">
                <span class="text-base">💡</span>
                <h3 class="text-xs font-semibold text-indigo-200 uppercase tracking-wider">
                  New to Ephemeral Privacy? Here is how your computer is protected:
                </h3>
              </div>
              <button 
                onclick={() => showFirstTimeGuide = false}
                class="text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
              >
                Hide Guide
              </button>
            </div>

            <div class="grid grid-cols-4 gap-3 text-xs">
              <div class="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div class="font-semibold text-cyan-300 flex items-center gap-1.5 mb-1">
                  <span>1.</span> Decoy Camouflage
                </div>
                <p class="text-slate-400 text-[11px] leading-relaxed">
                  Every time you browse, fake realistic searches are mixed in across Quad9, Mullvad, and Cloudflare so ad networks cannot build a profile on you.
                </p>
              </div>

              <div class="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div class="font-semibold text-emerald-300 flex items-center gap-1.5 mb-1">
                  <span>2.</span> Anti-ISP Packet Slicing
                </div>
                <p class="text-slate-400 text-[11px] leading-relaxed">
                  Your internet provider watches which websites you visit. This breaks your HTTPS packets into tiny slices so ISP inspection equipment cannot read the domain name.
                </p>
              </div>

              <div class="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div class="font-semibold text-amber-300 flex items-center gap-1.5 mb-1">
                  <span>3.</span> Tracker Sinkhole
                </div>
                <p class="text-slate-400 text-[11px] leading-relaxed">
                  Known telemetry endpoints, ad servers, and sneaky first-party CNAME disguised trackers are blocked before they can load.
                </p>
              </div>

              <div class="bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                <div class="font-semibold text-indigo-300 flex items-center gap-1.5 mb-1">
                  <span>4.</span> Clipboard & AI Guard
                </div>
                <p class="text-slate-400 text-[11px] leading-relaxed">
                  Tracking tokens (like <code class="text-slate-300">fbclid</code> or <code class="text-slate-300">utm_*</code>) are stripped from copied links, and sensitive data is censored before pasting into AI models.
                </p>
              </div>
            </div>
          </div>
        {/if}

        <div class="grid grid-cols-12 gap-6">
          <!-- LEFT: CAMOUFLAGE & ANTI-DPI CONTROLS -->
          <div class="col-span-5 flex flex-col gap-6">
            <!-- Camouflage Engine Card -->
            <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden flex flex-col justify-between">
              <div class="flex items-center justify-between mb-4">
                <div>
                  <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
                    <Radio class="w-4 h-4 text-cyan-400 animate-pulse" />
                    Search & Browsing Camouflage
                  </h3>
                  <p class="text-xs text-slate-400 mt-0.5">Emits decoy queries to poison tracking algorithms</p>
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
                  UPSTREAMS: QUAD9 ↔ MULLVAD ↔ CLOUDFLARE
                </div>
              </div>

              <!-- Camouflage Density Selector -->
              <div class="mt-4">
                <div class="flex items-center justify-between mb-2">
                  <span class="text-xs font-medium text-slate-300">Camouflage Density (Decoy Volume)</span>
                  <span class="text-[10px] text-slate-500">Poisson Distribution</span>
                </div>
                <div class="grid grid-cols-3 gap-2">
                  {#each [
                    { id: "Ghost", label: "Ghost", desc: "Light Decoys" },
                    { id: "Smokescreen", label: "Smokescreen", desc: "Balanced (Rec.)" },
                    { id: "HeavyFog", label: "Heavy Fog", desc: "Maximum" }
                  ] as mode}
                    <button
                      onclick={() => handleIntensityChange(mode.id)}
                      class="px-2.5 py-2 rounded-xl text-xs font-medium border transition-all text-center flex flex-col items-center gap-0.5 {status.chaff_intensity === mode.id ? 'bg-cyan-500/20 border-cyan-500 text-cyan-200 shadow-md shadow-cyan-500/10' : 'bg-slate-800/40 border-slate-700/60 text-slate-400 hover:text-slate-200'}"
                    >
                      <span class="font-semibold">{mode.label}</span>
                      <span class="text-[10px] opacity-75">{mode.desc}</span>
                    </button>
                  {/each}
                </div>
              </div>
            </div>

            <!-- Anti-DPI & SNI Slicing Status Card -->
            <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Lock class="w-4 h-4 text-emerald-400" />
                  Anti-ISP Snooping (Packet Slicing)
                </h3>
                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-semibold">
                  {status.sni_fragmentation ? "PROTECTING" : "OFF"}
                </span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                When you connect to an HTTPS website, your browser sends the website name in cleartext (SNI). This splits that first packet into microscopic fragments across TCP packets so ISP Deep Packet Inspection (DPI) scanners cannot read what domain you are visiting.
              </p>
              <div class="mt-3 flex items-center justify-between text-xs bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                <span class="text-slate-300">TLS 1.3 ClientHello Fragmentation</span>
                <span class="font-mono text-emerald-400 font-semibold">ACTIVE</span>
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
                <p class="text-[11px] text-slate-400">Strictly in RAM. Zero logs written to disk.</p>
              </div>
              <span class="text-[10px] font-mono text-slate-500">RAM RING BUFFER (50)</span>
            </div>

            <!-- Log stream list -->
            <div class="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[360px] max-h-[480px]">
              {#if recentEvents.length === 0}
                <div class="h-64 flex flex-col items-center justify-center text-slate-500 text-xs">
                  <Shield class="w-8 h-8 mb-2 opacity-30" />
                  No events recorded yet. Open any website in your browser to see live activity.
                </div>
              {:else}
                {#each recentEvents as ev (ev.id)}
                  <div class="bg-slate-950/80 border border-slate-800/80 rounded-xl p-3 text-xs flex flex-col gap-1 transition-all hover:border-slate-700">
                    <div class="flex items-center justify-between">
                      <span class="font-medium text-slate-200 flex items-center gap-2">
                        {#if ev.category === "DNS_CHAFF" || ev.category === "SEARCH_CHAFF"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800/50">CAMOUFLAGE</span>
                        {:else if ev.category === "TRACKER_BLOCKED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800/50">BLOCKED</span>
                        {:else if ev.category === "SNI_FRAGMENTED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/50">ISP SLICE</span>
                        {:else if ev.category === "DOH_RESOLVED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-400 border border-blue-800/50">ENCRYPTED DOH</span>
                        {:else if ev.category === "URL_SANITIZED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-400 border border-indigo-800/50">CLEANED LINK</span>
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
      </div>
    {:else if activeTab === "modules"}
      <!-- PRIVACY SHIELDS & CONTROLS -->
      <div class="max-w-4xl mx-auto space-y-4">
        <div>
          <h2 class="text-base font-bold text-slate-100">Privacy Shields & Anti-ISP Controls</h2>
          <p class="text-xs text-slate-400">Toggle individual privacy layers. Every module runs entirely locally in user space without requiring root or kernel extensions.</p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Module 1: Search & Browsing Camouflage -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Radio class="w-4 h-4 text-cyan-400" />
                  <span class="text-sm font-semibold text-slate-200">Search & Browsing Camouflage</span>
                </div>
                <button
                  aria-label="Toggle Camouflage Decoy Engine"
                  onclick={() => handleToggle("chaff", status.chaff_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.chaff_enabled ? 'bg-cyan-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.chaff_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Intersperses realistic decoy DNS & search queries with randomized Poisson delays across Quad9, Mullvad, and Cloudflare to make automated profiling useless.
              </p>
            </div>
            <div class="text-[10px] text-cyan-400/90 bg-cyan-950/40 p-2 rounded-lg border border-cyan-800/30">
              🛡️ <strong>Threat stopped:</strong> ISP and advertiser timeline profiling.
            </div>
          </div>

          <!-- Module 2: Anti-ISP SNI Packet Slicing -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Lock class="w-4 h-4 text-emerald-400" />
                  <span class="text-sm font-semibold text-slate-200">Anti-ISP Packet Slicing</span>
                </div>
                <button
                  aria-label="Toggle Anti-ISP SNI Slicing"
                  onclick={() => handleToggle("sni", status.sni_fragmentation)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.sni_fragmentation ? 'bg-emerald-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.sni_fragmentation ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Splits the unencrypted TLS 1.3 ClientHello packet right through the middle of the domain name so ISP Deep Packet Inspection boxes cannot see which websites you visit.
              </p>
            </div>
            <div class="text-[10px] text-emerald-400/90 bg-emerald-950/40 p-2 rounded-lg border border-emerald-800/30">
              🛡️ <strong>Threat stopped:</strong> ISP browsing history logging & surveillance.
            </div>
          </div>

          <!-- Module 3: Local DNS Sinkhole & CNAME Uncloaking -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <EyeOff class="w-4 h-4 text-amber-400" />
                  <span class="text-sm font-semibold text-slate-200">Ad Sinkhole & Stealth Tracker Blocker</span>
                </div>
                <button
                  aria-label="Toggle DNS Sinkhole"
                  onclick={() => handleToggle("dns", status.dns_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.dns_enabled ? 'bg-amber-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.dns_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Instantly drops connections to known tracking servers. Unmasks sneaky first-party CNAME aliases that websites use to bypass normal browser ad-blockers.
              </p>
            </div>
            <div class="text-[10px] text-amber-400/90 bg-amber-950/40 p-2 rounded-lg border border-amber-800/30">
              🛡️ <strong>Threat stopped:</strong> Cross-site telemetry & disguised analytics.
            </div>
          </div>

          <!-- Module 4: Clipboard Link Cleaner -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Filter class="w-4 h-4 text-indigo-400" />
                  <span class="text-sm font-semibold text-slate-200">Clipboard Tracking Link Stripper</span>
                </div>
                <button
                  aria-label="Toggle Clipboard Sanitizer"
                  onclick={() => handleToggle("clipboard", status.clipboard_cleaner)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.clipboard_cleaner ? 'bg-indigo-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.clipboard_cleaner ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Silently listens to your clipboard in the background. When you copy links from YouTube, TikTok, or emails, it removes 250+ tracking tokens (fbclid, utm_*, si) in &lt;1ms.
              </p>
            </div>
            <div class="text-[10px] text-indigo-400/90 bg-indigo-950/40 p-2 rounded-lg border border-indigo-800/30">
              🛡️ <strong>Threat stopped:</strong> Link tracking & identity tagging when sharing URLs.
            </div>
          </div>

          <!-- Module 5: OS System Proxy Integration -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Activity class="w-4 h-4 text-blue-400" />
                  <span class="text-sm font-semibold text-slate-200">OS Proxy Auto-Routing (:1080)</span>
                </div>
                <button
                  aria-label="Toggle System Proxy"
                  onclick={() => handleToggle("proxy", status.proxy_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.proxy_enabled ? 'bg-blue-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.proxy_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Automatically instructs macOS to route HTTP, HTTPS, and SOCKS5 connections through your local shield daemon. Automatically resets to direct connection on quit.
              </p>
            </div>
            <div class="text-[10px] text-blue-400/90 bg-blue-950/40 p-2 rounded-lg border border-blue-800/30">
              🛡️ <strong>Status:</strong> {status.os_proxy_active ? "Actively routing OS traffic" : "Inactive in OS settings"}
            </div>
          </div>

          <!-- Module 6: PII & Secret Redactor -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <ShieldCheck class="w-4 h-4 text-cyan-400" />
                  <span class="text-sm font-semibold text-slate-200">AI & Chat PII Masker</span>
                </div>
                <button
                  aria-label="Toggle Chat PII Masker"
                  onclick={() => handleToggle("pii", status.pii_redactor)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.pii_redactor ? 'bg-cyan-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.pii_redactor ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Masks credit card numbers (Luhn validated), API keys, passwords, emails, and phone numbers before they are sent to AI chat models like ChatGPT or Claude.
              </p>
            </div>
            <div class="text-[10px] text-cyan-400/90 bg-cyan-950/40 p-2 rounded-lg border border-cyan-800/30">
              🛡️ <strong>Threat stopped:</strong> Data leakage to AI model training sets.
            </div>
          </div>
        </div>
      </div>
    {:else if activeTab === "ai_sandbox"}
      <!-- AI & CHAT SANITIZER PLAYGROUND -->
      <div class="max-w-4xl mx-auto space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <Lock class="w-5 h-5 text-cyan-400" />
            AI & Chat Privacy Shield
          </h2>
          <p class="text-xs text-slate-400 mt-1">
            Before pasting your code or queries into ChatGPT, Claude, or Copilot, sanitize them here. Sensitive data is replaced with anonymous tokens that can be restored with 1 click after the AI responds.
          </p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Input Box -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col">
            <span class="text-xs font-semibold text-slate-300 mb-2 block">1. Your Original Prompt (Sensitive Data Stays Local)</span>
            <textarea
              bind:value={sandboxInput}
              class="flex-1 w-full bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-200 resize-none focus:outline-none focus:border-cyan-500 min-h-[160px]"
            ></textarea>
            <button
              onclick={runSandboxRedact}
              class="mt-3 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition-colors flex items-center justify-center gap-2"
            >
              <Zap class="w-3.5 h-3.5" />
              Scrub Secrets & Sensitive Data
            </button>
          </div>

          <!-- Output Box -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col">
            <div class="flex items-center justify-between mb-2">
              <span class="text-xs font-semibold text-cyan-300">2. Sanitized Prompt (Safe to Paste to AI)</span>
              {#if sandboxResult}
                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800/60">
                  {sandboxResult.redactions_count} Secrets Masked
                </span>
              {/if}
            </div>
            <div class="flex-1 w-full bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs font-mono text-slate-300 overflow-y-auto min-h-[160px] whitespace-pre-wrap select-all">
              {sandboxResult?.sanitized_text || "Click 'Scrub Secrets' to generate sanitized text..."}
            </div>
            <button
              onclick={runSandboxRestore}
              disabled={!sandboxResult}
              class="mt-3 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 transition-colors flex items-center justify-center gap-2 disabled:opacity-50"
            >
              <RefreshCw class="w-3.5 h-3.5" />
              3. Un-mask AI Answer (Restore Real Data)
            </button>
          </div>
        </div>

        {#if sandboxResult && Object.keys(sandboxResult.token_map).length > 0}
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4">
            <h4 class="text-xs font-semibold text-slate-300 mb-2">In-Memory Secret Vault (RAM Only, Never Sent Anywhere)</h4>
            <div class="grid grid-cols-2 gap-2">
              {#each Object.entries(sandboxResult.token_map) as [token, orig]}
                <div class="bg-slate-950/80 border border-slate-800 rounded-lg p-2 text-xs font-mono flex items-center justify-between">
                  <span class="text-cyan-400 font-bold">{token}</span>
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
              Restored AI Response (Original Sensitive Values Re-inserted):
            </h4>
            <p class="text-xs font-mono text-slate-200 select-all">{sandboxRestored}</p>
          </div>
        {/if}
      </div>
    {:else if activeTab === "url_cleaner"}
      <!-- LINK DE-TRACKER TOOL -->
      <div class="max-w-3xl mx-auto space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <Filter class="w-5 h-5 text-indigo-400" />
            Tracking Link Stripper
          </h2>
          <p class="text-xs text-slate-400 mt-1">
            Social networks (Facebook, Twitter, TikTok, YouTube) and email marketing platforms append tracking identifiers to links. Our background clipboard guard automatically strips them whenever you copy any link. You can also test any URL manually below:
          </p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 space-y-4 shadow-lg">
          <div>
            <span class="text-xs font-medium text-slate-300 block mb-1.5">Input URL with Tracking Parameters</span>
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
            Strip Tracking Parameters
          </button>

          {#if testUrlCleaned}
            <div class="pt-2 border-t border-slate-800/80">
              <div class="text-xs font-semibold text-indigo-300 mb-1 flex items-center gap-1.5">
                <CheckCircle class="w-4 h-4 text-emerald-400" />
                Sanitized URL (Clean &amp; Safe to Share):
              </div>
              <div class="bg-slate-950/90 border border-slate-800 rounded-xl p-3 text-xs font-mono text-emerald-300 break-all select-all">
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
            Operating System Telemetry Audit
          </h2>
          <p class="text-xs text-slate-400 mt-1">
            macOS, Windows, and Linux operating systems continuously ping diagnostic servers with unique machine IDs and crash telemetry. Below is the list of OS telemetry endpoints blocked by your local DNS sinkhole:
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
              <span class="text-[10px] font-mono px-2 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 shrink-0 font-semibold">
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
      <span>CAMOUFLAGE: {status.chaff_intensity}</span>
      <span>•</span>
      <span class={status.os_proxy_active ? "text-emerald-400" : "text-amber-400"}>
        OS ROUTING: {status.os_proxy_active ? "ACTIVE" : "INACTIVE"}
      </span>
    </div>
    <div>ZERO-KNOWLEDGE RAM ARCHITECTURE • NO DISK LOGS</div>
  </footer>
</div>
