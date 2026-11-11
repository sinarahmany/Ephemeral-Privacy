<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
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
    ChevronUp,
    Camera,
    Mic,
    Shuffle,
    Globe,
    Play,
    Clock,
    AppWindow
  } from "@lucide/svelte";

  // Navigation tab state
  let activeTab = $state<"dashboard" | "audit" | "modules" | "ai_sandbox" | "url_cleaner" | "os_telemetry">("dashboard");

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
    odoh_enabled: true,
    webrtc_shield: true,
    ja3_shuffle: true,
    hardware_sentinel_enabled: true,
    minimize_to_tray: true,
    chaff_intensity: "Smokescreen",
    upstream_resolver: "ODoH Relay + Rotated DoH",
    os_proxy_active: true,
  });

  let metrics = $state({
    queries_intercepted: 0,
    chaff_queries_sent: 0,
    trackers_blocked: 0,
    pii_sanitized: 0,
    sni_sliced_handshakes: 0,
    odoh_queries_relayed: 0,
    webrtc_leaks_blocked: 0,
    ja3_fingerprints_shuffled: 0,
    hardware_alerts_count: 0,
    camera_active: false,
    mic_active: false,
    camera_apps: [] as string[],
    mic_apps: [] as string[],
  });

  interface PrivacyEvent {
    id: number;
    timestamp: number;
    category: string;
    title: string;
    details: string;
    target: string;
  }

  interface AuditCheckResult {
    id: string;
    name: string;
    status: "PASS" | "WARN" | "FAIL";
    points_earned: number;
    max_points: number;
    latency_ms: number;
    summary: string;
    proof: string;
  }

  interface PrivacyAuditReport {
    score: number;
    timestamp: number;
    checks: AuditCheckResult[];
  }

  let recentEvents = $state<PrivacyEvent[]>([]);
  let isPanicLoading = $state(false);
  let panicMessage = $state("");

  // Privacy Audit & Leak Test states
  let auditReport = $state<PrivacyAuditReport | null>(null);
  let isAuditRunning = $state(false);
  let expandedAuditProofs = $state<Record<string, boolean>>({});

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

  async function runPrivacyAudit() {
    if (isAuditRunning) return;
    isAuditRunning = true;
    try {
      auditReport = await invoke("run_privacy_audit");
      await fetchStatus();
    } catch (e) {
      console.error("Failed running privacy audit:", e);
    } finally {
      isAuditRunning = false;
    }
  }

  function openAuditTab() {
    activeTab = "audit";
    if (!auditReport && !isAuditRunning) {
      runPrivacyAudit();
    }
  }

  function toggleProof(id: string) {
    expandedAuditProofs = {
      ...expandedAuditProofs,
      [id]: !expandedAuditProofs[id],
    };
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

    let unlisten: (() => void) | undefined;
    listen("privacy-state-changed", () => {
      fetchStatus();
    }).then((fn) => {
      unlisten = fn;
    });

    // Auto-refresh metrics every 1.5 seconds
    const interval = setInterval(fetchStatus, 1500);
    return () => {
      clearInterval(interval);
      if (unlisten) unlisten();
    };
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
        <div class="text-[11px] text-slate-400 flex items-center gap-2 mt-0.5 flex-wrap">
          <span class="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          <span>Shields Active</span>
          <span class="text-slate-600">•</span>
          <span class="font-mono text-slate-300">Proxy :1080</span>
          <span class="text-slate-600">•</span>
          <span class="font-mono text-cyan-400">
            {status.odoh_enabled ? "Oblivious DoH Relay" : "Encrypted DoH"}
          </span>
          <span class="text-slate-600">•</span>
          {#if metrics.camera_active || metrics.mic_active}
            <span class="px-2 py-0.5 rounded bg-rose-950/90 border border-rose-500/80 text-[10px] text-rose-200 font-semibold flex items-center gap-1 animate-pulse">
              {#if metrics.camera_active}<Camera class="w-3 h-3 text-rose-400" /> CAM{/if}
              {#if metrics.mic_active}<Mic class="w-3 h-3 text-rose-400" /> MIC{/if}
              LIVE
            </span>
          {:else}
            <span class="px-2 py-0.5 rounded bg-emerald-950/70 border border-emerald-800/60 text-[10px] text-emerald-300 font-medium flex items-center gap-1">
              <Camera class="w-3 h-3 opacity-70" />
              <Mic class="w-3 h-3 opacity-70" />
              {status.hardware_sentinel_enabled ? "Sensors Idle" : "Sensors Off"}
            </span>
          {/if}

          {#if !status.os_proxy_active}
            <button
              onclick={handleReassertProxy}
              class="ml-1 px-2 py-0.5 rounded bg-amber-950/80 hover:bg-amber-900 border border-amber-600/80 text-[10px] text-amber-300 font-semibold flex items-center gap-1 transition-colors animate-pulse"
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
        title="Fire an instant burst of realistic camouflage queries across ODoH relays, Quad9, Mullvad, and Cloudflare"
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

  <!-- HARDWARE SNOOPING SENTINEL ALERT BANNER -->
  {#if metrics.camera_active || metrics.mic_active}
    <div class="px-6 py-2.5 bg-gradient-to-r from-rose-950 via-red-950/90 to-rose-950 border-b border-rose-500/70 text-xs flex items-center justify-between text-rose-100 shrink-0 animate-pulse">
      <div class="flex items-center gap-3">
        <ShieldAlert class="w-4 h-4 text-rose-400 shrink-0" />
        <div class="flex items-center gap-2 flex-wrap">
          <span class="font-bold uppercase tracking-wider text-rose-200">Hardware Sensor Alert:</span>
          {#if metrics.camera_active}
            <span class="px-2 py-0.5 rounded bg-rose-900/90 border border-rose-500/60 font-mono text-[11px]">
              Camera Active ({metrics.camera_apps.length ? metrics.camera_apps.join(", ") : "Unknown App"})
            </span>
          {/if}
          {#if metrics.mic_active}
            <span class="px-2 py-0.5 rounded bg-rose-900/90 border border-rose-500/60 font-mono text-[11px]">
              Microphone Active ({metrics.mic_apps.length ? metrics.mic_apps.join(", ") : "Unknown App"})
            </span>
          {/if}
          <span class="text-rose-200/90">Verify that you intentionally started this recording or call.</span>
        </div>
      </div>
    </div>
  {/if}

  <!-- METRICS STRIP WITH FRIENDLY EXPLANATIONS -->
  <div class="grid grid-cols-5 gap-3 px-6 py-3.5 bg-slate-900/40 border-b border-slate-800/60 shrink-0">
    <!-- Metric 1: Web Requests & ODoH Relay -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between shadow-sm">
      <div class="min-w-0">
        <div class="flex items-center gap-1">
          <div class="text-[10px] font-medium uppercase tracking-wider text-slate-400 truncate">Web Requests</div>
          <button
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'queries' ? null : 'queries'}
            class="text-slate-500 hover:text-cyan-400 transition-colors shrink-0"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-xl font-bold font-mono text-slate-100 mt-0.5">{metrics.queries_intercepted}</div>
        <div class="text-[10px] text-blue-400 font-mono truncate">{metrics.odoh_queries_relayed} via ODoH</div>
      </div>
      <div class="w-8 h-8 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400 shrink-0">
        <Activity class="w-4 h-4" />
      </div>
    </div>

    <!-- Metric 2: Camouflage Decoys & JA3 -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between shadow-sm">
      <div class="min-w-0">
        <div class="flex items-center gap-1">
          <div class="text-[10px] font-medium uppercase tracking-wider text-slate-400 truncate">Decoy Camouflage</div>
          <button
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'chaff' ? null : 'chaff'}
            class="text-slate-500 hover:text-cyan-400 transition-colors shrink-0"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-xl font-bold font-mono text-cyan-400 mt-0.5">{metrics.chaff_queries_sent}</div>
        <div class="text-[10px] text-cyan-500/80 font-mono truncate">{metrics.ja3_fingerprints_shuffled} JA3 shuffled</div>
      </div>
      <div class="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 shrink-0">
        <Radio class="w-4 h-4 animate-pulse" />
      </div>
    </div>

    <!-- Metric 3: Trackers & Ads Blocked -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between shadow-sm">
      <div class="min-w-0">
        <div class="flex items-center gap-1">
          <div class="text-[10px] font-medium uppercase tracking-wider text-slate-400 truncate">Trackers Blocked</div>
          <button
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'trackers' ? null : 'trackers'}
            class="text-slate-500 hover:text-amber-400 transition-colors shrink-0"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-xl font-bold font-mono text-amber-400 mt-0.5">{metrics.trackers_blocked}</div>
        <div class="text-[10px] text-slate-500 truncate">Ads &amp; spyware dropped</div>
      </div>
      <div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 shrink-0">
        <EyeOff class="w-4 h-4" />
      </div>
    </div>

    <!-- Metric 4: WebRTC Direct IP Leaks Stopped -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between shadow-sm">
      <div class="min-w-0">
        <div class="flex items-center gap-1">
          <div class="text-[10px] font-medium uppercase tracking-wider text-slate-400 truncate">WebRTC Leaks</div>
          <button
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'webrtc' ? null : 'webrtc'}
            class="text-slate-500 hover:text-rose-400 transition-colors shrink-0"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-xl font-bold font-mono text-rose-400 mt-0.5">{metrics.webrtc_leaks_blocked}</div>
        <div class="text-[10px] text-slate-500 truncate">STUN IP probes blocked</div>
      </div>
      <div class="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 shrink-0">
        <Globe class="w-4 h-4" />
      </div>
    </div>

    <!-- Metric 5: Anti-ISP Handshake Slices -->
    <div class="bg-slate-900/80 border border-slate-800 rounded-xl p-3 flex items-center justify-between shadow-sm">
      <div class="min-w-0">
        <div class="flex items-center gap-1">
          <div class="text-[10px] font-medium uppercase tracking-wider text-slate-400 truncate">ISP Slices &amp; HW</div>
          <button
            type="button"
            onclick={() => activeInfoModal = activeInfoModal === 'sni' ? null : 'sni'}
            class="text-slate-500 hover:text-emerald-400 transition-colors shrink-0"
            title="What is this?"
          >
            <Info class="w-3 h-3" />
          </button>
        </div>
        <div class="text-xl font-bold font-mono text-emerald-400 mt-0.5">{metrics.sni_sliced_handshakes}</div>
        <div class="text-[10px] text-slate-500 truncate">{metrics.hardware_alerts_count} cam/mic alerts</div>
      </div>
      <div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 shrink-0">
        <Lock class="w-4 h-4" />
      </div>
    </div>
  </div>

  <!-- EXPANDABLE EXPLANATION BANNER (If user clicked an info icon) -->
  {#if activeInfoModal}
    <div class="px-6 py-3 bg-slate-900/90 border-b border-cyan-800/40 text-xs flex items-center justify-between text-slate-200 shrink-0">
      <div class="flex items-center gap-2">
        <Info class="w-4 h-4 text-cyan-400 shrink-0" />
        {#if activeInfoModal === 'queries'}
          <span><strong>Web Requests &amp; ODoH Relay:</strong> Sites routed through your local proxy with RFC 9230 Oblivious DoH enabled — the Relay sees your IP (never the site name), while the DNS resolver sees the site name (never your IP).</span>
        {:else if activeInfoModal === 'chaff'}
          <span><strong>Decoy Camouflage &amp; JA3 Shuffling:</strong> Synthetic realistic DNS queries fired with randomized Poisson delays while rotating TLS cipher suite order and ALPN headers across outbound daemon traffic.</span>
        {:else if activeInfoModal === 'trackers'}
          <span><strong>Trackers &amp; Ads Blocked:</strong> Known tracking brokers, telemetry endpoints, and disguised CNAME trackers dropped before leaving your computer.</span>
        {:else if activeInfoModal === 'webrtc'}
          <span><strong>WebRTC IP Leak Shield:</strong> Intercepts sneaky browser/conferencing STUN &amp; TURN bypass probes (ports 3478, 5349, 19302–19309 &amp; SOCKS5 UDP) so sites cannot uncover your true home ISP IP.</span>
        {:else if activeInfoModal === 'sni'}
          <span><strong>ISP Snooping Blocks &amp; Hardware Alerts:</strong> Splits HTTPS ClientHello packets across TLS record boundaries to blind ISP inspection boxes, while watching Camera/Mic hardware sensors for silent capture.</span>
        {/if}
      </div>
      <button onclick={() => activeInfoModal = null} class="text-xs text-slate-400 hover:text-white px-2 py-0.5">Dismiss</button>
    </div>
  {/if}

  <!-- NAVIGATION TABS -->
  <div class="px-6 border-b border-slate-800/80 bg-slate-950/40 flex gap-1 shrink-0 overflow-x-auto">
    <button
      onclick={() => (activeTab = "dashboard")}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'dashboard' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Activity class="w-4 h-4" />
      Dashboard &amp; Live Activity
    </button>
    <button
      onclick={openAuditTab}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'audit' ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <ShieldCheck class="w-4 h-4" />
      Privacy Audit &amp; Leak Test
    </button>
    <button
      onclick={() => (activeTab = "modules")}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'modules' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Sliders class="w-4 h-4" />
      Shields &amp; Anti-ISP Controls
    </button>
    <button
      onclick={() => (activeTab = "ai_sandbox")}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'ai_sandbox' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Lock class="w-4 h-4" />
      AI &amp; Chat Shield
    </button>
    <button
      onclick={() => (activeTab = "url_cleaner")}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'url_cleaner' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Filter class="w-4 h-4" />
      Link Stripper
    </button>
    <button
      onclick={() => (activeTab = "os_telemetry")}
      class="px-3.5 py-3 text-xs font-medium border-b-2 transition-colors flex items-center gap-1.5 whitespace-nowrap {activeTab === 'os_telemetry' ? 'border-cyan-400 text-cyan-300' : 'border-transparent text-slate-400 hover:text-slate-200'}"
    >
      <Layers class="w-4 h-4" />
      OS Telemetry
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
                  {status.odoh_enabled ? "ODOH RELAY ↔ CLOUDFLARE / CRYPTO.SX" : "UPSTREAMS: QUAD9 ↔ MULLVAD ↔ CLOUDFLARE"}
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

            <!-- Anti-DPI, ODoH, JA3 & WebRTC Stack Card -->
            <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 shadow-lg">
              <div class="flex items-center justify-between mb-2">
                <h3 class="text-sm font-semibold text-slate-200 flex items-center gap-2">
                  <Lock class="w-4 h-4 text-emerald-400" />
                  Zero-Leak Network Transport
                </h3>
                <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-semibold">
                  {status.sni_fragmentation ? "PROTECTING" : "OFF"}
                </span>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed">
                Splits TLS ClientHello packets across record boundaries to hide visited domains, rotates JA3 cipher suite orders, relays DNS via Oblivious DoH, and drops WebRTC STUN IP-leak probes.
              </p>
              <div class="mt-3 space-y-1.5 text-xs">
                <div class="flex items-center justify-between bg-slate-950/60 px-3 py-2 rounded-xl border border-slate-800/80">
                  <span class="text-slate-300">Oblivious DoH (RFC 9230 Relay)</span>
                  <span class="font-mono font-semibold {status.odoh_enabled ? 'text-cyan-400' : 'text-slate-500'}">{status.odoh_enabled ? "RELAYING" : "OFF"}</span>
                </div>
                <div class="flex items-center justify-between bg-slate-950/60 px-3 py-2 rounded-xl border border-slate-800/80">
                  <span class="text-slate-300">WebRTC Direct IP Leak Shield</span>
                  <span class="font-mono font-semibold {status.webrtc_shield ? 'text-rose-400' : 'text-slate-500'}">{status.webrtc_shield ? "SHIELDING" : "OFF"}</span>
                </div>
                <div class="flex items-center justify-between bg-slate-950/60 px-3 py-2 rounded-xl border border-slate-800/80">
                  <span class="text-slate-300">TLS Record Split &amp; JA3 Shuffling</span>
                  <span class="font-mono font-semibold {status.sni_fragmentation && status.ja3_shuffle ? 'text-emerald-400' : 'text-amber-400'}">{status.sni_fragmentation || status.ja3_shuffle ? "ACTIVE" : "OFF"}</span>
                </div>
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
            <div class="flex-1 overflow-y-auto space-y-2 pr-1 min-h-[360px] max-h-[500px]">
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
                        {:else if ev.category === "WEBRTC_BLOCKED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-700/60">WEBRTC BLOCK</span>
                        {:else if ev.category === "HARDWARE_ALERT"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-950 text-red-300 border border-red-600/70 animate-pulse">HW ALERT</span>
                        {:else if ev.category === "HARDWARE_CLEAR"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-300 border border-emerald-800/50">SENSOR IDLE</span>
                        {:else if ev.category === "ODOH_RESOLVED"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-teal-950 text-teal-300 border border-teal-700/60">ODOH RELAY</span>
                        {:else if ev.category === "PRIVACY_AUDIT"}
                          <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-violet-950 text-violet-300 border border-violet-700/60">AUDIT</span>
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
    {:else if activeTab === "audit"}
      <!-- INTERACTIVE PRIVACY AUDIT & LEAK TEST PANEL -->
      <div class="max-w-4xl mx-auto space-y-5">
        <div class="bg-gradient-to-br from-slate-900 via-slate-900 to-emerald-950/30 border border-slate-800 rounded-2xl p-6 shadow-xl flex items-center justify-between gap-6">
          <div class="flex items-center gap-5">
            <div class="w-24 h-24 rounded-2xl bg-slate-950/90 border-2 flex flex-col items-center justify-center shrink-0 {auditReport ? (auditReport.score >= 85 ? 'border-emerald-500/80 shadow-lg shadow-emerald-500/15' : auditReport.score >= 60 ? 'border-amber-500/80' : 'border-rose-500/80') : 'border-slate-700'}">
              <span class="text-3xl font-black font-mono {auditReport ? (auditReport.score >= 85 ? 'text-emerald-400' : auditReport.score >= 60 ? 'text-amber-400' : 'text-rose-400') : 'text-slate-500'}">
                {auditReport ? auditReport.score : "--"}
              </span>
              <span class="text-[10px] font-mono uppercase tracking-wider text-slate-400">/ 100 SCORE</span>
            </div>
            <div>
              <div class="flex items-center gap-2">
                <h2 class="text-base font-bold text-slate-100">Interactive Privacy Audit &amp; Leak Test</h2>
                {#if auditReport}
                  <span class="text-[10px] font-mono px-2 py-0.5 rounded font-semibold {auditReport.score >= 85 ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/60' : auditReport.score >= 60 ? 'bg-amber-950 text-amber-300 border border-amber-700/60' : 'bg-rose-950 text-rose-300 border border-rose-700/60'}">
                    {auditReport.score >= 85 ? "STEALTH VERIFIED" : auditReport.score >= 60 ? "PARTIAL SHIELD" : "LEAK RISK"}
                  </span>
                {/if}
              </div>
              <p class="text-xs text-slate-400 mt-1 max-w-xl leading-relaxed">
                Runs real-time local &amp; encrypted network diagnostics against your active proxy daemon (<code class="text-slate-300">:1080</code>), RFC 9230 Oblivious DoH relays, WebRTC STUN blocking rules, TLS record slicing, and hardware camera/microphone sensors.
              </p>
              {#if auditReport}
                <div class="text-[10px] font-mono text-slate-500 mt-2 flex items-center gap-2">
                  <Clock class="w-3 h-3" />
                  Last verified at {new Date(auditReport.timestamp * 1000).toLocaleTimeString()}
                </div>
              {/if}
            </div>
          </div>

          <button
            onclick={runPrivacyAudit}
            disabled={isAuditRunning}
            class="px-5 py-3 rounded-xl bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-xs font-semibold text-white transition-all shadow-lg shadow-emerald-900/40 flex items-center gap-2 shrink-0"
          >
            {#if isAuditRunning}
              <RefreshCw class="w-4 h-4 animate-spin" />
              Running Live Probes...
            {:else}
              <Play class="w-4 h-4" />
              Run Live Security Audit
            {/if}
          </button>
        </div>

        {#if auditReport}
          <div class="grid grid-cols-1 gap-3">
            {#each auditReport.checks as check (check.id)}
              <div class="bg-slate-900/70 border rounded-2xl p-4 transition-all {check.status === 'PASS' ? 'border-emerald-900/60' : check.status === 'WARN' ? 'border-amber-800/60' : 'border-rose-800/70'}">
                <div class="flex items-center justify-between gap-4">
                  <div class="flex items-center gap-3">
                    {#if check.status === "PASS"}
                      <div class="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shrink-0">
                        <CheckCircle class="w-4 h-4" />
                      </div>
                    {:else if check.status === "WARN"}
                      <div class="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                        <AlertTriangle class="w-4 h-4" />
                      </div>
                    {:else}
                      <div class="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400 shrink-0">
                        <ShieldAlert class="w-4 h-4" />
                      </div>
                    {/if}
                    <div>
                      <div class="flex items-center gap-2">
                        <span class="text-sm font-semibold text-slate-100">{check.name}</span>
                        <span class="text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold {check.status === 'PASS' ? 'bg-emerald-950 text-emerald-300 border border-emerald-700/50' : check.status === 'WARN' ? 'bg-amber-950 text-amber-300 border border-amber-700/50' : 'bg-rose-950 text-rose-300 border border-rose-700/50'}">
                          {check.status}
                        </span>
                      </div>
                      <p class="text-xs text-slate-400 mt-0.5">{check.summary}</p>
                    </div>
                  </div>

                  <div class="flex items-center gap-3 shrink-0">
                    <span class="text-[11px] font-mono text-slate-400">{check.latency_ms}ms</span>
                    <span class="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                      {check.points_earned}/{check.max_points} pts
                    </span>
                    <button
                      onclick={() => toggleProof(check.id)}
                      class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 flex items-center gap-1 transition-colors"
                    >
                      Proof
                      {#if expandedAuditProofs[check.id]}
                        <ChevronUp class="w-3 h-3" />
                      {:else}
                        <ChevronDown class="w-3 h-3" />
                      {/if}
                    </button>
                  </div>
                </div>

                {#if expandedAuditProofs[check.id]}
                  <div class="mt-3 pt-3 border-t border-slate-800/80 text-[11px] font-mono text-cyan-300/90 bg-slate-950/70 rounded-xl p-3 select-all break-all">
                    {check.proof}
                  </div>
                {/if}
              </div>
            {/each}
          </div>
        {:else if !isAuditRunning}
          <div class="bg-slate-900/50 border border-slate-800 rounded-2xl p-10 text-center text-xs text-slate-400">
            Click <strong class="text-emerald-300">Run Live Security Audit</strong> above to run live DNS, WebRTC, proxy, TLS, and hardware sensor tests.
          </div>
        {/if}
      </div>
    {:else if activeTab === "modules"}
      <!-- PRIVACY SHIELDS & CONTROLS -->
      <div class="max-w-4xl mx-auto space-y-4">
        <div>
          <h2 class="text-base font-bold text-slate-100">Privacy Shields & Anti-ISP Controls</h2>
          <p class="text-xs text-slate-400">Toggle individual privacy layers. Every module runs entirely locally in user space without requiring root or kernel extensions.</p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <!-- Module 0A: Oblivious DoH (ODoH) Relay Mode -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Globe class="w-4 h-4 text-teal-400" />
                  <span class="text-sm font-semibold text-slate-200">Oblivious DoH (ODoH) Relay Mode</span>
                </div>
                <button
                  aria-label="Toggle Oblivious DoH Relay"
                  onclick={() => handleToggle("odoh", status.odoh_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.odoh_enabled ? 'bg-teal-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.odoh_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Uses RFC 9230 HPKE encryption through blind Relays (Fastly/Numa) before reaching Cloudflare/Crypto.sx DNS. The Relay sees your IP only; the Target sees the domain only.
              </p>
            </div>
            <div class="text-[10px] text-teal-300/90 bg-teal-950/40 p-2 rounded-lg border border-teal-800/30">
              🛡️ <strong>Threat stopped:</strong> Upstream DNS resolvers correlating your IP with browsing history.
            </div>
          </div>

          <!-- Module 0B: WebRTC Direct IP Leak Shield -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <ShieldAlert class="w-4 h-4 text-rose-400" />
                  <span class="text-sm font-semibold text-slate-200">WebRTC Direct IP Leak Shield</span>
                </div>
                <button
                  aria-label="Toggle WebRTC IP Leak Shield"
                  onclick={() => handleToggle("webrtc", status.webrtc_shield)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.webrtc_shield ? 'bg-rose-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.webrtc_shield ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Intercepts sneaky WebRTC STUN/TURN UDP &amp; proxy bypass requests (ports 3478, 5349, 19302–19309, SOCKS5 UDP) used by browsers and chat apps to uncover your real ISP &amp; LAN IPs.
              </p>
            </div>
            <div class="text-[10px] text-rose-300/90 bg-rose-950/40 p-2 rounded-lg border border-rose-800/30">
              🛡️ <strong>Threat stopped:</strong> Proxy/VPN bypass via WebRTC STUN discovery.
            </div>
          </div>

          <!-- Module 0C: JA3 / JA4 TLS Fingerprint Shuffling -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Shuffle class="w-4 h-4 text-violet-400" />
                  <span class="text-sm font-semibold text-slate-200">JA3 / JA4 TLS Fingerprint Shuffling</span>
                </div>
                <button
                  aria-label="Toggle JA3 TLS Fingerprint Shuffling"
                  onclick={() => handleToggle("ja3", status.ja3_shuffle)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.ja3_shuffle ? 'bg-violet-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.ja3_shuffle ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Rotates cipher suite order and ALPN tokens across outbound TLS connections, splits ClientHello records across multiple TLS frames, and normalizes plaintext HTTP User-Agent headers.
              </p>
            </div>
            <div class="text-[10px] text-violet-300/90 bg-violet-950/40 p-2 rounded-lg border border-violet-800/30">
              🛡️ <strong>Threat stopped:</strong> Passive TLS stack fingerprinting across sessions.
            </div>
          </div>

          <!-- Module 0D: Hardware Snooping Sentinel -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <Camera class="w-4 h-4 text-emerald-400" />
                  <span class="text-sm font-semibold text-slate-200">Camera &amp; Mic Snooping Sentinel</span>
                </div>
                <button
                  aria-label="Toggle Hardware Snooping Sentinel"
                  onclick={() => handleToggle("sentinel", status.hardware_sentinel_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.hardware_sentinel_enabled ? 'bg-emerald-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.hardware_sentinel_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-3">
                Polls low-level CoreAudio &amp; CoreMediaIO device state silently (without triggering OS mic/camera permission prompts) to immediately flag which app activates your webcam or microphone.
              </p>
            </div>
            <div class="text-[10px] text-emerald-300/90 bg-emerald-950/40 p-2 rounded-lg border border-emerald-800/30">
              🛡️ <strong>Status:</strong> {metrics.camera_active || metrics.mic_active ? "SENSOR STREAM ACTIVE RIGHT NOW" : "Both sensors currently idle & guarded"}
            </div>
          </div>

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

          <!-- Module 7: Menu Bar Tray Companion -->
          <div class="bg-slate-900/60 border border-slate-800 rounded-2xl p-4 flex flex-col justify-between col-span-2">
            <div>
              <div class="flex items-center justify-between mb-2">
                <div class="flex items-center gap-2">
                  <AppWindow class="w-4 h-4 text-sky-400" />
                  <span class="text-sm font-semibold text-slate-200">Run Quietly in Menu Bar When Closing Window</span>
                </div>
                <button
                  aria-label="Toggle Run in Menu Bar on Close"
                  onclick={() => handleToggle("minimize_to_tray", status.minimize_to_tray)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.minimize_to_tray ? 'bg-sky-500' : 'bg-slate-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.minimize_to_tray ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
              <p class="text-xs text-slate-400 leading-relaxed mb-2">
                When enabled, clicking the red close button hides the window to the macOS Menu Bar companion so your privacy shields stay active uninterrupted. To stop all protection and restore direct networking, choose <strong>Quit Ephemeral Privacy</strong> from the Menu Bar icon (or press <kbd class="px-1 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">Cmd+Q</kbd>).
              </p>
            </div>
            <div class="text-[10px] text-sky-300/90 bg-sky-950/40 p-2 rounded-lg border border-sky-800/30">
              🖥️ <strong>Behavior:</strong> {status.minimize_to_tray ? "Closing window hides to Menu Bar tray (protection continues)" : "Closing window exits app and resets OS network proxy"}
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
