<script lang="ts">
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import { listen } from "@tauri-apps/api/event";
  import {
    Activity,
    AlertTriangle,
    Camera,
    Check,
    CheckCircle,
    ChevronDown,
    ChevronUp,
    Clock,
    Copy,
    Filter,
    Info,
    Lock,
    Mic,
    Play,
    Radio,
    RefreshCw,
    ShieldAlert,
    ShieldCheck,
    Sliders,
    Zap
  } from "@lucide/svelte";

  type NavSection = "overview" | "protections" | "audit" | "tools";
  type EventFilter = "all" | "alerts" | "network";

  let activeSection = $state<NavSection>("overview");
  let eventFilter = $state<EventFilter>("all");
  let showQuickGuide = $state(false);
  let activeGlossary = $state<string | null>(null);
  let showTelemetryList = $state(false);
  let showVaultMap = $state(false);

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
    blocklist_rules: 0,
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

  interface OsItem {
    id: string;
    name: string;
    os: string;
    description: string;
    risk_level: string;
  }

  let recentEvents = $state<PrivacyEvent[]>([]);
  let telemetryList = $state<OsItem[]>([]);
  let auditReport = $state<PrivacyAuditReport | null>(null);

  let isAuditRunning = $state(false);
  let expandedAuditProofs = $state<Record<string, boolean>>({});
  let decoySentFeedback = $state(false);

  // Two-step inline emergency disconnect state (avoids disruptive modal confirm)
  let panicArmed = $state(false);
  let isPanicLoading = $state(false);
  let panicMessage = $state("");

  // Privacy Tools states
  let sandboxInput = $state(
    "Please review this code for user alex.morgan@fintech.io. Authorization: Bearer sk-ant-api03-9999888877776666555544443333222211110000. Customer card on file is 4532 0151 1283 0366."
  );
  let sandboxResult = $state<{
    sanitized_text: string;
    redactions_count: number;
    token_map: Record<string, string>;
  } | null>(null);
  let sandboxRestored = $state("");
  let copiedMasked = $state(false);

  let testUrlInput = $state(
    "https://store.example.com/item/4829?utm_source=facebook&utm_medium=cpc&utm_campaign=winter_sale&fbclid=IwAR29184712048124&gclid=Cj0KCQjwgJ8&ref_src=twsrc"
  );
  let testUrlCleaned = $state<string | null>(null);
  let copiedUrl = $state(false);

  let filteredEvents = $derived.by(() => {
    if (eventFilter === "alerts") {
      return recentEvents.filter((ev) =>
        ["TRACKER_BLOCKED", "WEBRTC_BLOCKED", "HARDWARE_ALERT", "PANIC_TRIGGERED"].includes(ev.category)
      );
    }
    if (eventFilter === "network") {
      return recentEvents.filter((ev) =>
        ["ODOH_RESOLVED", "DOH_RESOLVED", "SNI_FRAGMENTED", "DNS_CHAFF", "SEARCH_CHAFF"].includes(ev.category)
      );
    }
    return recentEvents;
  });

  function formatCategoryBadge(category: string): { label: string; tone: string } {
    switch (category) {
      case "TRACKER_BLOCKED":
        return { label: "Blocked", tone: "bg-amber-500/10 text-amber-300 border-amber-500/25" };
      case "WEBRTC_BLOCKED":
        return { label: "IP Leak Stopped", tone: "bg-rose-500/15 text-rose-300 border-rose-500/30" };
      case "HARDWARE_ALERT":
        return { label: "Sensor Alert", tone: "bg-rose-500/20 text-rose-200 border-rose-500/40" };
      case "HARDWARE_CLEAR":
        return { label: "Sensor Idle", tone: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25" };
      case "ODOH_RESOLVED":
        return { label: "Double-Blind DNS", tone: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25" };
      case "DOH_RESOLVED":
        return { label: "Encrypted DNS", tone: "bg-cyan-500/10 text-cyan-300 border-cyan-500/25" };
      case "SNI_FRAGMENTED":
        return { label: "ISP Blinded", tone: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25" };
      case "DNS_CHAFF":
      case "SEARCH_CHAFF":
        return { label: "Decoy Noise", tone: "bg-cyan-500/10 text-cyan-300 border-cyan-500/25" };
      case "URL_SANITIZED":
        return { label: "Link Cleaned", tone: "bg-emerald-500/10 text-emerald-300 border-emerald-500/25" };
      case "PRIVACY_AUDIT":
        return { label: "Security Check", tone: "bg-cyan-500/10 text-cyan-300 border-cyan-500/25" };
      default:
        return { label: "System", tone: "bg-white/[0.05] text-zinc-300 border-white/10" };
    }
  }

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

  function openAuditSection() {
    activeSection = "audit";
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
      decoySentFeedback = true;
      setTimeout(() => {
        decoySentFeedback = false;
      }, 2000);
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

  function armPanic() {
    panicArmed = true;
    setTimeout(() => {
      panicArmed = false;
    }, 5000);
  }

  async function confirmPanic() {
    panicArmed = false;
    isPanicLoading = true;
    try {
      panicMessage = await invoke("trigger_panic");
      await fetchStatus();
    } catch (e) {
      panicMessage = `Reset failed: ${e}`;
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

  async function copyText(text: string, which: "masked" | "url") {
    try {
      await navigator.clipboard.writeText(text);
      if (which === "masked") {
        copiedMasked = true;
        setTimeout(() => (copiedMasked = false), 1800);
      } else {
        copiedUrl = true;
        setTimeout(() => (copiedUrl = false), 1800);
      }
    } catch (e) {
      console.error("Clipboard write error:", e);
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

    const interval = setInterval(fetchStatus, 1500);
    return () => {
      clearInterval(interval);
      if (unlisten) unlisten();
    };
  });
</script>

<!-- APP SHELL: STEALTH SIDEBAR + BREATHABLE WORKSPACE -->
<div class="h-screen w-screen flex bg-[#050709] text-zinc-100 antialiased overflow-hidden">
  <!-- LEFT NAVIGATION RAIL -->
  <aside class="w-56 shrink-0 bg-[#080b0f] border-r border-white/[0.07] flex flex-col justify-between p-4">
    <div class="space-y-6">
      <!-- Brand Lockup -->
      <div class="flex items-center gap-3 px-1">
        <div class="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center shrink-0">
          <ShieldCheck class="w-5 h-5 text-emerald-400" />
        </div>
        <div class="min-w-0">
          <div class="text-sm font-semibold tracking-tight text-zinc-100 leading-none">Ephemeral</div>
          <div class="flex items-center gap-1.5 mt-1.5">
            <span class="w-1.5 h-1.5 rounded-full {status.os_proxy_active && status.proxy_enabled ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}"></span>
            <span class="text-[11px] font-medium {status.os_proxy_active && status.proxy_enabled ? 'text-emerald-400' : 'text-amber-300'}">
              {status.os_proxy_active && status.proxy_enabled ? "Shield Active" : "Shield Paused"}
            </span>
          </div>
        </div>
      </div>

      <!-- Primary Navigation -->
      <nav class="space-y-1" aria-label="Main sections">
        <button
          onclick={() => (activeSection = "overview")}
          class="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-colors {activeSection === 'overview' ? 'bg-white/[0.07] text-zinc-100 border border-white/[0.08]' : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] border border-transparent'}"
        >
          <Activity class="w-4 h-4 {activeSection === 'overview' ? 'text-emerald-400' : 'text-zinc-500'}" />
          <span>Overview</span>
        </button>

        <button
          onclick={() => (activeSection = "protections")}
          class="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-colors {activeSection === 'protections' ? 'bg-white/[0.07] text-zinc-100 border border-white/[0.08]' : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] border border-transparent'}"
        >
          <Sliders class="w-4 h-4 {activeSection === 'protections' ? 'text-emerald-400' : 'text-zinc-500'}" />
          <span>Protections</span>
        </button>

        <button
          onclick={openAuditSection}
          class="w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-[13px] font-medium transition-colors {activeSection === 'audit' ? 'bg-white/[0.07] text-zinc-100 border border-white/[0.08]' : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] border border-transparent'}"
        >
          <span class="flex items-center gap-2.5">
            <Lock class="w-4 h-4 {activeSection === 'audit' ? 'text-emerald-400' : 'text-zinc-500'}" />
            <span>Security Check</span>
          </span>
          {#if auditReport}
            <span class="text-[11px] font-mono tabular-nums px-1.5 py-0.5 rounded {auditReport.score >= 85 ? 'text-emerald-300 bg-emerald-500/10' : 'text-amber-300 bg-amber-500/10'}">
              {auditReport.score}
            </span>
          {/if}
        </button>

        <button
          onclick={() => (activeSection = "tools")}
          class="w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-[13px] font-medium transition-colors {activeSection === 'tools' ? 'bg-white/[0.07] text-zinc-100 border border-white/[0.08]' : 'text-zinc-400 hover:text-zinc-200 hover:bg-white/[0.03] border border-transparent'}"
        >
          <Filter class="w-4 h-4 {activeSection === 'tools' ? 'text-emerald-400' : 'text-zinc-500'}" />
          <span>Privacy Tools</span>
        </button>
      </nav>
    </div>

    <!-- Bottom Controls & Hardware Status -->
    <div class="space-y-3 pt-4 border-t border-white/[0.07]">
      <!-- Hardware Sensor Watchdog Pill -->
      <div class="px-3 py-2 rounded-lg border text-xs flex items-center justify-between {metrics.camera_active || metrics.mic_active ? 'bg-rose-950/60 border-rose-500/50 text-rose-200 animate-pulse' : 'bg-[#0b0f14] border-white/[0.06] text-zinc-400'}">
        <span class="flex items-center gap-1.5 truncate">
          <Camera class="w-3.5 h-3.5 {metrics.camera_active ? 'text-rose-400' : 'text-zinc-500'}" />
          <Mic class="w-3.5 h-3.5 {metrics.mic_active ? 'text-rose-400' : 'text-zinc-500'}" />
          <span class="truncate">
            {#if metrics.camera_active || metrics.mic_active}
              {metrics.camera_active && metrics.mic_active ? "Cam & Mic On" : metrics.camera_active ? "Camera On" : "Mic On"}
            {:else}
              {status.hardware_sentinel_enabled ? "Sensors Idle" : "Watchdog Off"}
            {/if}
          </span>
        </span>
      </div>

      <!-- Decoy Noise Action -->
      <button
        onclick={triggerManualBurst}
        class="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-[#10151c] hover:bg-[#161d26] border border-white/[0.08] text-xs font-medium text-zinc-200 transition-colors"
        title="Mix harmless background searches with your traffic to confuse ad trackers"
      >
        {#if decoySentFeedback}
          <Check class="w-3.5 h-3.5 text-emerald-400" />
          <span class="text-emerald-300">Decoys Sent</span>
        {:else}
          <Radio class="w-3.5 h-3.5 text-cyan-400" />
          <span>Send Decoy Noise</span>
        {/if}
      </button>

      <!-- Emergency Disconnect with clean 2-step confirmation -->
      {#if !panicArmed}
        <button
          onclick={armPanic}
          disabled={isPanicLoading}
          class="w-full flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-rose-950/40 hover:bg-rose-950/70 border border-rose-500/30 text-xs font-medium text-rose-300 transition-colors disabled:opacity-50"
          title="Instantly turns off system routing, clears DNS cache, and empties clipboard"
        >
          <Zap class="w-3.5 h-3.5 text-rose-400" />
          <span>{isPanicLoading ? "Resetting..." : "Restore Direct Wi-Fi"}</span>
        </button>
      {:else}
        <div class="grid grid-cols-2 gap-1.5">
          <button
            onclick={confirmPanic}
            class="px-2 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-[11px] font-semibold text-white transition-colors"
          >
            Confirm
          </button>
          <button
            onclick={() => (panicArmed = false)}
            class="px-2 py-2 rounded-lg bg-white/[0.06] hover:bg-white/[0.1] text-[11px] font-medium text-zinc-300 transition-colors"
          >
            Cancel
          </button>
        </div>
      {/if}
    </div>
  </aside>

  <!-- MAIN WORKSPACE -->
  <div class="flex-1 flex flex-col min-w-0 cyber-grid-bg overflow-hidden">
    <!-- CONTEXTUAL ALERT BARS (ONLY VISIBLE WHEN NEEDED) -->
    {#if metrics.camera_active || metrics.mic_active}
      <div class="px-7 py-2.5 bg-rose-950/80 border-b border-rose-500/40 text-xs flex items-center justify-between text-rose-100 shrink-0">
        <div class="flex items-center gap-2.5">
          <ShieldAlert class="w-4 h-4 text-rose-400 shrink-0" />
          <span>
            <strong class="font-semibold">Hardware Access Detected:</strong>
            {#if metrics.camera_active}
              Camera in use by <span class="font-mono text-rose-200">{metrics.camera_apps.length ? metrics.camera_apps.join(", ") : "Unknown App"}</span>
            {/if}
            {#if metrics.camera_active && metrics.mic_active} · {/if}
            {#if metrics.mic_active}
              Microphone in use by <span class="font-mono text-rose-200">{metrics.mic_apps.length ? metrics.mic_apps.join(", ") : "Unknown App"}</span>
            {/if}
          </span>
        </div>
        <span class="text-[11px] text-rose-200/80">Make sure you opened this app</span>
      </div>
    {/if}

    {#if !status.os_proxy_active}
      <div class="px-7 py-2.5 bg-amber-950/60 border-b border-amber-500/35 text-xs flex items-center justify-between text-amber-100 shrink-0">
        <div class="flex items-center gap-2">
          <AlertTriangle class="w-4 h-4 text-amber-400 shrink-0" />
          <span>Your Mac is currently bypassing the privacy shield (direct connection active).</span>
        </div>
        <button
          onclick={handleReassertProxy}
          class="px-3 py-1 rounded-md bg-amber-500 hover:bg-amber-400 text-zinc-950 font-semibold text-[11px] transition-colors"
        >
          Re-enable Shield
        </button>
      </div>
    {/if}

    {#if panicMessage}
      <div class="px-7 py-2.5 bg-emerald-950/70 border-b border-emerald-500/35 text-xs flex items-center justify-between text-emerald-100 shrink-0">
        <span class="flex items-center gap-2">
          <CheckCircle class="w-4 h-4 text-emerald-400 shrink-0" />
          {panicMessage}
        </span>
        <button onclick={() => (panicMessage = "")} class="text-emerald-300 hover:text-white text-[11px]">Dismiss</button>
      </div>
    {/if}

    <!-- SCROLLABLE CONTENT AREA -->
    <main class="flex-1 overflow-y-auto px-7 py-6">
      {#if activeSection === "overview"}
        <div class="max-w-5xl mx-auto space-y-5">
          <!-- HERO STATUS SURFACE -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl p-6">
            <div class="flex items-start justify-between gap-6">
              <div class="space-y-2 max-w-xl">
                <div class="flex items-center gap-2.5">
                  <span class="w-2.5 h-2.5 rounded-full {status.os_proxy_active && status.proxy_enabled ? 'bg-emerald-400' : 'bg-amber-400'}"></span>
                  <h1 class="text-xl font-semibold tracking-tight text-zinc-100">
                    {status.os_proxy_active && status.proxy_enabled ? "Your internet connection is private" : "Privacy shield is paused"}
                  </h1>
                </div>
                <p class="text-[13px] text-zinc-400 leading-relaxed">
                  {#if status.os_proxy_active && status.proxy_enabled}
                    Web lookups use {status.odoh_enabled ? "double-blind DNS relays" : "encrypted DNS"}, trackers and IP leak probes are blocked locally, and decoy noise keeps advertisers guessing.
                  {:else}
                    Automatic OS routing is paused right now. Turn on the system shield above or inside Protections to resume full protection.
                  {/if}
                </p>

                <div class="pt-1 flex items-center gap-4">
                  <button
                    onclick={() => (showQuickGuide = !showQuickGuide)}
                    class="text-xs font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1 transition-colors"
                  >
                    <Info class="w-3.5 h-3.5" />
                    {showQuickGuide ? "Hide beginner guide" : "New to Ephemeral? See what happens behind the scenes"}
                    {#if showQuickGuide}
                      <ChevronUp class="w-3.5 h-3.5" />
                    {:else}
                      <ChevronDown class="w-3.5 h-3.5" />
                    {/if}
                  </button>
                </div>
              </div>

              <!-- Decoy Strength Switcher -->
              <div class="shrink-0 space-y-2 text-right">
                <div class="text-[11px] font-medium text-zinc-400">Decoy Noise Level</div>
                <div class="inline-flex p-1 rounded-lg bg-[#050709] border border-white/[0.07]">
                  {#each [
                    { id: "Ghost", label: "Light" },
                    { id: "Smokescreen", label: "Balanced" },
                    { id: "HeavyFog", label: "Heavy" }
                  ] as level}
                    <button
                      onclick={() => handleIntensityChange(level.id)}
                      class="px-3 py-1.5 rounded-md text-xs font-medium transition-colors {status.chaff_intensity === level.id ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30' : 'text-zinc-400 hover:text-zinc-200 border border-transparent'}"
                    >
                      {level.label}
                    </button>
                  {/each}
                </div>
                <div class="text-[11px] font-mono text-zinc-500">
                  {status.odoh_enabled ? "Double-Blind ODoH" : "Encrypted DoH"} · Proxy :1080
                </div>
              </div>
            </div>

            {#if showQuickGuide}
              <div class="mt-5 pt-4 border-t border-white/[0.07] grid grid-cols-4 gap-5 text-xs">
                <div>
                  <div class="font-medium text-zinc-200 mb-1">1. Hides Sites From ISP</div>
                  <p class="text-zinc-400 leading-relaxed">Splits encrypted website names so your internet provider cannot build a browsing log.</p>
                </div>
                <div>
                  <div class="font-medium text-zinc-200 mb-1">2. Confuses Ad Profilers</div>
                  <p class="text-zinc-400 leading-relaxed">Blends harmless decoy lookups into your browsing so tracking profiles break down.</p>
                </div>
                <div>
                  <div class="font-medium text-zinc-200 mb-1">3. Blocks Ads &amp; IP Leaks</div>
                  <p class="text-zinc-400 leading-relaxed">Drops spyware domains and prevents video/chat apps from leaking your home IP.</p>
                </div>
                <div>
                  <div class="font-medium text-zinc-200 mb-1">4. Guards Camera &amp; Links</div>
                  <p class="text-zinc-400 leading-relaxed">Alerts on camera/mic activation and removes tracking tags when you copy URLs.</p>
                </div>
              </div>
            {/if}
          </section>

          <!-- UNIFIED 4-COLUMN TELEMETRY STRIP -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl overflow-hidden">
            <div class="grid grid-cols-4 divide-x divide-white/[0.06]">
              <div class="p-4">
                <div class="flex items-center justify-between text-xs text-zinc-400">
                  <span>Sites Protected</span>
                  <button
                    onclick={() => (activeGlossary = activeGlossary === "sites" ? null : "sites")}
                    class="text-zinc-500 hover:text-emerald-400 transition-colors"
                    aria-label="Explain Sites Protected"
                  >
                    <Info class="w-3.5 h-3.5" />
                  </button>
                </div>
                <div class="text-2xl font-semibold font-mono tabular-nums text-zinc-100 mt-1.5">
                  {metrics.queries_intercepted}
                </div>
                <div class="text-[11px] font-mono tabular-nums text-emerald-400/90 mt-1">
                  {metrics.odoh_queries_relayed} double-blind lookups
                </div>
              </div>

              <div class="p-4">
                <div class="flex items-center justify-between text-xs text-zinc-400">
                  <span>Ads &amp; IP Leaks Stopped</span>
                  <button
                    onclick={() => (activeGlossary = activeGlossary === "blocks" ? null : "blocks")}
                    class="text-zinc-500 hover:text-amber-400 transition-colors"
                    aria-label="Explain Ads & IP Leaks Stopped"
                  >
                    <Info class="w-3.5 h-3.5" />
                  </button>
                </div>
                <div class="text-2xl font-semibold font-mono tabular-nums text-amber-400 mt-1.5">
                  {metrics.trackers_blocked + metrics.webrtc_leaks_blocked}
                </div>
                <div class="text-[11px] font-mono tabular-nums text-zinc-400 mt-1">
                  {metrics.trackers_blocked} trackers · {metrics.webrtc_leaks_blocked} IP leaks
                </div>
              </div>

              <div class="p-4">
                <div class="flex items-center justify-between text-xs text-zinc-400">
                  <span>Decoy Noise Sent</span>
                  <button
                    onclick={() => (activeGlossary = activeGlossary === "decoys" ? null : "decoys")}
                    class="text-zinc-500 hover:text-cyan-400 transition-colors"
                    aria-label="Explain Decoy Noise Sent"
                  >
                    <Info class="w-3.5 h-3.5" />
                  </button>
                </div>
                <div class="text-2xl font-semibold font-mono tabular-nums text-cyan-400 mt-1.5">
                  {metrics.chaff_queries_sent}
                </div>
                <div class="text-[11px] font-mono tabular-nums text-zinc-400 mt-1">
                  {metrics.ja3_fingerprints_shuffled} rotated TLS signatures
                </div>
              </div>

              <div class="p-4">
                <div class="flex items-center justify-between text-xs text-zinc-400">
                  <span>ISP Snoops Blinded</span>
                  <button
                    onclick={() => (activeGlossary = activeGlossary === "isp" ? null : "isp")}
                    class="text-zinc-500 hover:text-emerald-400 transition-colors"
                    aria-label="Explain ISP Snoops Blinded"
                  >
                    <Info class="w-3.5 h-3.5" />
                  </button>
                </div>
                <div class="text-2xl font-semibold font-mono tabular-nums text-zinc-100 mt-1.5">
                  {metrics.sni_sliced_handshakes}
                </div>
                <div class="text-[11px] font-mono tabular-nums text-zinc-400 mt-1">
                  {metrics.hardware_alerts_count} cam/mic alerts logged
                </div>
              </div>
            </div>

            {#if activeGlossary}
              <div class="px-4 py-2.5 bg-[#10151c] border-t border-white/[0.06] text-xs flex items-center justify-between text-zinc-300">
                <span>
                  {#if activeGlossary === "sites"}
                    Total web &amp; app connections routed through your Mac's private shield instead of going directly to your ISP's plain DNS.
                  {:else if activeGlossary === "blocks"}
                    Trackers dropped before loading plus WebRTC STUN/TURN leak requests stopped before websites could discover your home IP.
                  {:else if activeGlossary === "decoys"}
                    Fake background lookups sent with randomized timing while cycling TLS cipher profiles so advertisers see only noise.
                  {:else if activeGlossary === "isp"}
                    HTTPS handshakes split across multiple TLS records so ISP Deep Packet Inspection cannot read website hostnames.
                  {/if}
                </span>
                <button onclick={() => (activeGlossary = null)} class="text-zinc-400 hover:text-zinc-100 ml-4 shrink-0">Close</button>
              </div>
            {/if}
          </section>

          <!-- LIVE ACTIVITY STREAM (RAM-ONLY FLAT FEED) -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl overflow-hidden">
            <div class="px-5 py-3.5 border-b border-white/[0.06] flex items-center justify-between gap-4">
              <div>
                <h2 class="text-sm font-semibold text-zinc-100">Live Protection Feed</h2>
                <p class="text-[11px] text-zinc-500">Kept strictly in RAM — zero history ever saved to disk.</p>
              </div>

              <div class="inline-flex p-0.5 rounded-lg bg-[#050709] border border-white/[0.07] text-[11px]">
                {#each [
                  { id: "all", label: "All Events" },
                  { id: "alerts", label: "Blocks & Alerts" },
                  { id: "network", label: "Network Stealth" }
                ] as tab}
                  <button
                    onclick={() => (eventFilter = tab.id as EventFilter)}
                    class="px-2.5 py-1 rounded-md font-medium transition-colors {eventFilter === tab.id ? 'bg-white/[0.08] text-zinc-100' : 'text-zinc-400 hover:text-zinc-200'}"
                  >
                    {tab.label}
                  </button>
                {/each}
              </div>
            </div>

            {#if filteredEvents.length === 0}
              <div class="py-12 px-6 text-center text-xs text-zinc-500 space-y-2">
                <p class="text-zinc-300 font-medium">Waiting for browser or app activity</p>
                <p>Open any website in Safari or Chrome — encrypted DNS lookups, blocked trackers, and ISP blinding will stream here live.</p>
              </div>
            {:else}
              <div class="max-h-[340px] overflow-y-auto divide-y divide-white/[0.05]">
                {#each filteredEvents as ev (ev.id)}
                  {@const badge = formatCategoryBadge(ev.category)}
                  <div class="px-5 py-3 hover:bg-white/[0.02] transition-colors flex items-start justify-between gap-4">
                    <div class="min-w-0 space-y-1">
                      <div class="flex items-center gap-2.5 flex-wrap">
                        <span class="px-2 py-0.5 rounded border text-[10px] font-medium shrink-0 {badge.tone}">
                          {badge.label}
                        </span>
                        <span class="text-xs font-medium text-zinc-200">{ev.title}</span>
                      </div>
                      <p class="text-[11px] text-zinc-400 leading-relaxed">{ev.details}</p>
                    </div>
                    <div class="text-right shrink-0 space-y-1">
                      <div class="text-[11px] font-mono tabular-nums text-zinc-500">
                        {new Date(ev.timestamp * 1000).toLocaleTimeString()}
                      </div>
                      <div class="text-[10px] font-mono text-emerald-400/75 max-w-[190px] truncate">
                        {ev.target}
                      </div>
                    </div>
                  </div>
                {/each}
              </div>
            {/if}
          </section>
        </div>

      {:else if activeSection === "protections"}
        <!-- CLEAN GROUPED PROTECTIONS -->
        <div class="max-w-3xl mx-auto space-y-6">
          <div>
            <h1 class="text-lg font-semibold tracking-tight text-zinc-100">Privacy Protections</h1>
            <p class="text-xs text-zinc-400 mt-1">Turn individual shields on or off. Recommended settings are enabled by default.</p>
          </div>

          <!-- Group 1: Browsing & Network Stealth -->
          <div class="space-y-2">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-zinc-400 px-1">Browsing &amp; Network Stealth</h2>
            <div class="bg-[#0b0f14] border border-white/[0.07] rounded-xl divide-y divide-white/[0.06]">
              {#each [
                {
                  key: "odoh",
                  on: status.odoh_enabled,
                  title: "Hide Site Lookups (Double-Blind DNS)",
                  tag: "RFC 9230 ODoH",
                  desc: "Separates your IP address from the website name you look up across a relay and target so neither sees both."
                },
                {
                  key: "sni",
                  on: status.sni_fragmentation,
                  title: "Hide Visited Websites From Your ISP",
                  tag: "TLS Record Split",
                  desc: "Breaks initial HTTPS website headers across tiny network frames so internet provider scanners cannot read domains."
                },
                {
                  key: "dns",
                  on: status.dns_enabled,
                  title: "Block Ads, Trackers & Disguised Analytics",
                  tag: metrics.blocklist_rules > 0
                    ? `${metrics.blocklist_rules.toLocaleString()} RAM Rules`
                    : "Sinkhole + CNAME",
                  desc: "Drops connections to known ad brokers, spyware servers, and CNAME-cloaked trackers before they load."
                },
                {
                  key: "chaff",
                  on: status.chaff_enabled,
                  title: "Confuse Profilers With Decoy Noise",
                  tag: "Traffic Camouflage",
                  desc: "Mixes realistic decoy lookups at random intervals with your real browsing so tracking profiles become unreliable."
                },
                {
                  key: "ja3",
                  on: status.ja3_shuffle,
                  title: "Disguise Browser Connection Signature",
                  tag: "JA3/JA4 Shuffling",
                  desc: "Rotates encryption cipher suite order and headers on outbound traffic to prevent passive fingerprinting."
                }
              ] as item}
                <div class="px-5 py-4 flex items-center justify-between gap-6">
                  <div class="space-y-1 min-w-0">
                    <div class="flex items-center gap-2">
                      <span class="text-sm font-medium text-zinc-100">{item.title}</span>
                      <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] text-zinc-400 border border-white/[0.06]">{item.tag}</span>
                    </div>
                    <p class="text-xs text-zinc-400 leading-relaxed">{item.desc}</p>
                  </div>
                  <button
                    aria-label={`Toggle ${item.title}`}
                    onclick={() => handleToggle(item.key, item.on)}
                    class="w-11 h-6 rounded-full transition-colors relative shrink-0 {item.on ? 'bg-emerald-500' : 'bg-zinc-700'}"
                  >
                    <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {item.on ? 'translate-x-5' : ''}"></span>
                  </button>
                </div>
              {/each}
            </div>
          </div>

          <!-- Group 2: Leak & Hardware Watchdogs -->
          <div class="space-y-2">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-zinc-400 px-1">IP Leak &amp; Sensor Defense</h2>
            <div class="bg-[#0b0f14] border border-white/[0.07] rounded-xl divide-y divide-white/[0.06]">
              <div class="px-5 py-4 flex items-center justify-between gap-6">
                <div class="space-y-1 min-w-0">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-zinc-100">Stop Real IP Leaks in Calls &amp; Chat</span>
                    <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] text-zinc-400 border border-white/[0.06]">WebRTC Shield</span>
                  </div>
                  <p class="text-xs text-zinc-400 leading-relaxed">
                    Blocks STUN/TURN leak probes (ports 3478, 5349, 19302) and SOCKS5 UDP bypasses so apps cannot discover your true home IP.
                  </p>
                </div>
                <button
                  aria-label="Toggle WebRTC IP Leak Shield"
                  onclick={() => handleToggle("webrtc", status.webrtc_shield)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.webrtc_shield ? 'bg-emerald-500' : 'bg-zinc-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.webrtc_shield ? 'translate-x-5' : ''}"></span>
                </button>
              </div>

              <div class="px-5 py-4 flex items-center justify-between gap-6">
                <div class="space-y-1 min-w-0">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-zinc-100">Camera &amp; Microphone Watchdog</span>
                    <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-white/[0.04] text-zinc-400 border border-white/[0.06]">Hardware Sentinel</span>
                  </div>
                  <p class="text-xs text-zinc-400 leading-relaxed">
                    Quietly monitors CoreAudio and CoreMediaIO hardware state (with zero macOS permission popups) and alerts whenever a camera or mic turns on.
                  </p>
                </div>
                <button
                  aria-label="Toggle Camera & Mic Watchdog"
                  onclick={() => handleToggle("sentinel", status.hardware_sentinel_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.hardware_sentinel_enabled ? 'bg-emerald-500' : 'bg-zinc-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.hardware_sentinel_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
            </div>
          </div>

          <!-- Group 3: App & System Preferences -->
          <div class="space-y-2">
            <h2 class="text-xs font-semibold uppercase tracking-wider text-zinc-400 px-1">App &amp; Clipboard Preferences</h2>
            <div class="bg-[#0b0f14] border border-white/[0.07] rounded-xl divide-y divide-white/[0.06]">
              <div class="px-5 py-4 flex items-center justify-between gap-6">
                <div class="space-y-1 min-w-0">
                  <div class="text-sm font-medium text-zinc-100">Strip Tracking Codes From Copied Links</div>
                  <p class="text-xs text-zinc-400 leading-relaxed">
                    Removes tracking tokens like <code class="text-zinc-300">fbclid</code>, <code class="text-zinc-300">utm_*</code>, and share IDs automatically when you copy URLs.
                  </p>
                </div>
                <button
                  aria-label="Toggle Clipboard Link Stripper"
                  onclick={() => handleToggle("clipboard", status.clipboard_cleaner)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.clipboard_cleaner ? 'bg-emerald-500' : 'bg-zinc-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.clipboard_cleaner ? 'translate-x-5' : ''}"></span>
                </button>
              </div>

              <div class="px-5 py-4 flex items-center justify-between gap-6">
                <div class="space-y-1 min-w-0">
                  <div class="text-sm font-medium text-zinc-100">Route System Traffic Through Shield</div>
                  <p class="text-xs text-zinc-400 leading-relaxed">
                    Sets your Mac's active network proxy to <code class="text-zinc-300">127.0.0.1:1080</code> while running, and automatically restores direct networking on quit.
                  </p>
                </div>
                <button
                  aria-label="Toggle OS Proxy Routing"
                  onclick={() => handleToggle("proxy", status.proxy_enabled)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.proxy_enabled ? 'bg-emerald-500' : 'bg-zinc-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.proxy_enabled ? 'translate-x-5' : ''}"></span>
                </button>
              </div>

              <div class="px-5 py-4 flex items-center justify-between gap-6">
                <div class="space-y-1 min-w-0">
                  <div class="text-sm font-medium text-zinc-100">Run Quietly in Menu Bar When Window Closes</div>
                  <p class="text-xs text-zinc-400 leading-relaxed">
                    Clicking close keeps shields running in your macOS Menu Bar. Choose <strong>Quit Ephemeral Privacy</strong> from the Menu Bar or press <kbd class="px-1 py-0.5 rounded bg-white/[0.06] text-zinc-300 font-mono text-[11px]">Cmd+Q</kbd> to exit completely.
                  </p>
                </div>
                <button
                  aria-label="Toggle Run in Menu Bar on Close"
                  onclick={() => handleToggle("minimize_to_tray", status.minimize_to_tray)}
                  class="w-11 h-6 rounded-full transition-colors relative shrink-0 {status.minimize_to_tray ? 'bg-emerald-500' : 'bg-zinc-700'}"
                >
                  <span class="absolute top-1 left-1 w-4 h-4 rounded-full bg-white transition-transform {status.minimize_to_tray ? 'translate-x-5' : ''}"></span>
                </button>
              </div>
            </div>
          </div>
        </div>

      {:else if activeSection === "audit"}
        <!-- INTERACTIVE PRIVACY CHECKUP & TELEMETRY DOMAINS -->
        <div class="max-w-3xl mx-auto space-y-5">
          <!-- Top Summary Strip -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl p-6 flex items-center justify-between gap-6">
            <div class="flex items-center gap-5">
              <div class="px-4 py-3 rounded-xl bg-[#050709] border border-white/[0.08] text-center min-w-[96px]">
                <div class="text-3xl font-bold font-mono tabular-nums {auditReport ? (auditReport.score >= 85 ? 'text-emerald-400' : auditReport.score >= 60 ? 'text-amber-400' : 'text-rose-400') : 'text-zinc-500'}">
                  {auditReport ? auditReport.score : "--"}
                </div>
                <div class="text-[10px] font-mono text-zinc-500 mt-0.5">/ 100 SCORE</div>
              </div>

              <div class="space-y-1">
                <div class="flex items-center gap-2.5">
                  <h1 class="text-lg font-semibold tracking-tight text-zinc-100">Live Security Check</h1>
                  {#if auditReport}
                    <span class="text-[11px] font-mono px-2 py-0.5 rounded border {auditReport.score >= 85 ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25' : auditReport.score >= 60 ? 'bg-amber-500/10 text-amber-300 border-amber-500/25' : 'bg-rose-500/10 text-rose-300 border-rose-500/25'}">
                      {auditReport.score >= 85 ? "VERIFIED" : auditReport.score >= 60 ? "PARTIAL" : "AT RISK"}
                    </span>
                  {/if}
                </div>
                <p class="text-xs text-zinc-400 max-w-md leading-relaxed">
                  Tests real local proxy routing, double-blind ODoH DNS, WebRTC IP leak blocking, TLS record slicing, tracker sinkholing, and hardware sensors.
                </p>
                {#if auditReport}
                  <div class="text-[11px] font-mono text-zinc-500 inline-flex items-center gap-1.5 pt-0.5">
                    <Clock class="w-3 h-3" />
                    Last verified {new Date(auditReport.timestamp * 1000).toLocaleTimeString()}
                  </div>
                {/if}
              </div>
            </div>

            <button
              onclick={runPrivacyAudit}
              disabled={isAuditRunning}
              class="px-4 py-2.5 rounded-lg bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 text-xs font-semibold text-zinc-950 transition-colors inline-flex items-center gap-2 shrink-0"
            >
              {#if isAuditRunning}
                <RefreshCw class="w-4 h-4 animate-spin" />
                Checking...
              {:else}
                <Play class="w-3.5 h-3.5" />
                Run Check
              {/if}
            </button>
          </section>

          {#if auditReport}
            <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl divide-y divide-white/[0.06]">
              {#each auditReport.checks as check (check.id)}
                <div class="p-4">
                  <div class="flex items-center justify-between gap-4">
                    <div class="flex items-start gap-3 min-w-0">
                      {#if check.status === "PASS"}
                        <CheckCircle class="w-4 h-4 text-emerald-400 mt-0.5 shrink-0" />
                      {:else if check.status === "WARN"}
                        <AlertTriangle class="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      {:else}
                        <ShieldAlert class="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                      {/if}
                      <div class="space-y-0.5 min-w-0">
                        <div class="flex items-center gap-2">
                          <span class="text-sm font-medium text-zinc-100">{check.name}</span>
                          <span class="text-[10px] font-mono px-1.5 py-0.5 rounded border {check.status === 'PASS' ? 'bg-emerald-500/10 text-emerald-300 border-emerald-500/25' : check.status === 'WARN' ? 'bg-amber-500/10 text-amber-300 border-amber-500/25' : 'bg-rose-500/10 text-rose-300 border-rose-500/25'}">
                            {check.status}
                          </span>
                        </div>
                        <p class="text-xs text-zinc-400 leading-relaxed">{check.summary}</p>
                      </div>
                    </div>

                    <div class="flex items-center gap-3 shrink-0">
                      <span class="text-[11px] font-mono tabular-nums text-zinc-500">{check.latency_ms}ms</span>
                      <span class="text-[11px] font-mono tabular-nums text-zinc-300">{check.points_earned}/{check.max_points}</span>
                      <button
                        onclick={() => toggleProof(check.id)}
                        class="px-2.5 py-1 rounded-md bg-white/[0.04] hover:bg-white/[0.08] border border-white/[0.07] text-[11px] text-zinc-300 inline-flex items-center gap-1 transition-colors"
                      >
                        Details
                        {#if expandedAuditProofs[check.id]}
                          <ChevronUp class="w-3 h-3" />
                        {:else}
                          <ChevronDown class="w-3 h-3" />
                        {/if}
                      </button>
                    </div>
                  </div>

                  {#if expandedAuditProofs[check.id]}
                    <div class="mt-3 ml-7 text-[11px] font-mono text-cyan-300 bg-[#050709] border border-white/[0.07] rounded-lg p-3 select-all break-all">
                      {check.proof}
                    </div>
                  {/if}
                </div>
              {/each}
            </section>
          {:else if !isAuditRunning}
            <div class="bg-[#0b0f14] border border-white/[0.07] rounded-xl p-10 text-center text-xs text-zinc-400">
              Click <strong class="text-zinc-200">Run Check</strong> to run live leak and configuration diagnostics.
            </div>
          {/if}

          <!-- Blocked OS Telemetry Expandable List -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl overflow-hidden">
            <button
              onclick={() => (showTelemetryList = !showTelemetryList)}
              class="w-full px-5 py-3.5 flex items-center justify-between text-left hover:bg-white/[0.02] transition-colors"
            >
              <div>
                <div class="text-sm font-medium text-zinc-200">
                  Built-In OS Telemetry Blocklist ({telemetryList.length})
                </div>
                <div class="text-xs text-zinc-500">macOS, Windows, and Linux diagnostic servers dropped silently by the local sinkhole.</div>
              </div>
              <span class="text-xs text-zinc-400 inline-flex items-center gap-1 shrink-0">
                {showTelemetryList ? "Hide" : "Inspect"}
                {#if showTelemetryList}
                  <ChevronUp class="w-3.5 h-3.5" />
                {:else}
                  <ChevronDown class="w-3.5 h-3.5" />
                {/if}
              </span>
            </button>

            {#if showTelemetryList}
              <div class="border-t border-white/[0.06] divide-y divide-white/[0.05]">
                {#each telemetryList as item}
                  <div class="px-5 py-3 flex items-start justify-between gap-4">
                    <div class="space-y-0.5">
                      <div class="flex items-center gap-2">
                        <span class="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-white/[0.05] text-zinc-300">{item.os}</span>
                        <span class="text-xs font-medium text-zinc-200">{item.name}</span>
                      </div>
                      <p class="text-[11px] text-zinc-400">{item.description}</p>
                    </div>
                    <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 shrink-0">
                      BLOCKED
                    </span>
                  </div>
                {/each}
              </div>
            {/if}
          </section>
        </div>

      {:else if activeSection === "tools"}
        <!-- CLEAN 2-TOOL PRIVACY WORKBENCH -->
        <div class="max-w-4xl mx-auto space-y-6">
          <div>
            <h1 class="text-lg font-semibold tracking-tight text-zinc-100">Privacy Tools</h1>
            <p class="text-xs text-zinc-400 mt-1">Hide private secrets before using AI chatbots, or strip tracking codes from URLs.</p>
          </div>

          <!-- Tool 1: URL Tracking Link Cleaner -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl p-5 space-y-3.5">
            <div>
              <h2 class="text-sm font-semibold text-zinc-100">Remove Tracking Codes From Links</h2>
              <p class="text-xs text-zinc-400 mt-0.5">Your copied links are cleaned automatically in the background. You can also test or clean any link manually below.</p>
            </div>

            <div class="flex gap-2.5">
              <input
                type="text"
                bind:value={testUrlInput}
                aria-label="URL with tracking parameters"
                class="flex-1 bg-[#050709] border border-white/[0.08] rounded-lg px-3.5 py-2 text-xs font-mono text-zinc-200 focus:outline-none focus:border-emerald-500/60 select-text"
              />
              <button
                onclick={runUrlCleaner}
                class="px-4 py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-semibold text-zinc-950 transition-colors shrink-0"
              >
                Clean Link
              </button>
            </div>

            {#if testUrlCleaned}
              <div class="bg-[#050709] border border-white/[0.07] rounded-lg p-3 flex items-center justify-between gap-3">
                <div class="text-xs font-mono text-emerald-300 break-all select-all">{testUrlCleaned}</div>
                <button
                  onclick={() => copyText(testUrlCleaned || "", "url")}
                  class="px-2.5 py-1 rounded bg-white/[0.05] hover:bg-white/[0.1] text-[11px] text-zinc-200 inline-flex items-center gap-1 shrink-0 transition-colors"
                >
                  {#if copiedUrl}
                    <Check class="w-3 h-3 text-emerald-400" />
                    Copied
                  {:else}
                    <Copy class="w-3 h-3" />
                    Copy
                  {/if}
                </button>
              </div>
            {/if}
          </section>

          <!-- Tool 2: Hide Secrets Before Using AI -->
          <section class="bg-[#0b0f14] border border-white/[0.07] rounded-xl p-5 space-y-4">
            <div class="flex items-center justify-between">
              <div>
                <h2 class="text-sm font-semibold text-zinc-100">Hide Private Details Before Pasting to AI</h2>
                <p class="text-xs text-zinc-400 mt-0.5">Replaces emails, API keys, and credit cards locally with safe placeholders. Restore real values after the AI replies.</p>
              </div>
              {#if sandboxResult}
                <span class="text-[11px] font-mono px-2.5 py-1 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/25">
                  {sandboxResult.redactions_count} Masked
                </span>
              {/if}
            </div>

            <div class="grid grid-cols-2 gap-4">
              <div class="space-y-2">
                <label for="ai-prompt-input" class="text-xs font-medium text-zinc-300 block">1. Original Text (Stays on This Mac)</label>
                <textarea
                  id="ai-prompt-input"
                  bind:value={sandboxInput}
                  class="w-full bg-[#050709] border border-white/[0.08] rounded-lg p-3 text-xs font-mono text-zinc-200 resize-none focus:outline-none focus:border-emerald-500/60 h-36 select-text"
                ></textarea>
                <button
                  onclick={runSandboxRedact}
                  class="w-full py-2 rounded-lg bg-emerald-500 hover:bg-emerald-400 text-xs font-semibold text-zinc-950 transition-colors"
                >
                  Mask Secrets
                </button>
              </div>

              <div class="space-y-2">
                <div class="flex items-center justify-between">
                  <span class="text-xs font-medium text-zinc-300">2. Safe Text to Paste</span>
                  {#if sandboxResult?.sanitized_text}
                    <button
                      onclick={() => copyText(sandboxResult?.sanitized_text || "", "masked")}
                      class="text-[11px] text-zinc-400 hover:text-zinc-100 inline-flex items-center gap-1"
                    >
                      {#if copiedMasked}
                        <Check class="w-3 h-3 text-emerald-400" />
                        Copied
                      {:else}
                        <Copy class="w-3 h-3" />
                        Copy Safe Text
                      {/if}
                    </button>
                  {/if}
                </div>
                <div class="w-full bg-[#050709] border border-white/[0.08] rounded-lg p-3 text-xs font-mono text-zinc-300 overflow-y-auto h-36 whitespace-pre-wrap select-all">
                  {sandboxResult?.sanitized_text || "Click 'Mask Secrets' to sanitize text."}
                </div>
                <button
                  onclick={runSandboxRestore}
                  disabled={!sandboxResult}
                  class="w-full py-2 rounded-lg bg-white/[0.06] hover:bg-white/[0.1] border border-white/[0.08] text-xs font-medium text-zinc-200 transition-colors disabled:opacity-40"
                >
                  Restore Real Details From AI Output
                </button>
              </div>
            </div>

            {#if sandboxRestored}
              <div class="bg-[#050709] border border-emerald-500/30 rounded-lg p-3 text-xs space-y-1">
                <div class="font-medium text-emerald-400">Restored Text:</div>
                <p class="font-mono text-zinc-200 select-all break-words">{sandboxRestored}</p>
              </div>
            {/if}

            {#if sandboxResult && Object.keys(sandboxResult.token_map).length > 0}
              <div class="pt-1">
                <button
                  onclick={() => (showVaultMap = !showVaultMap)}
                  class="text-[11px] text-zinc-400 hover:text-zinc-200 inline-flex items-center gap-1"
                >
                  {showVaultMap ? "Hide temporary placeholder map" : "View temporary placeholder map"}
                  {#if showVaultMap}
                    <ChevronUp class="w-3 h-3" />
                  {:else}
                    <ChevronDown class="w-3 h-3" />
                  {/if}
                </button>

                {#if showVaultMap}
                  <div class="mt-2.5 grid grid-cols-2 gap-2">
                    {#each Object.entries(sandboxResult.token_map) as [token, orig]}
                      <div class="bg-[#050709] border border-white/[0.06] rounded-lg px-3 py-2 text-[11px] font-mono flex items-center justify-between gap-2">
                        <span class="text-emerald-400 font-semibold">{token}</span>
                        <span class="text-zinc-500 truncate">{orig}</span>
                      </div>
                    {/each}
                  </div>
                {/if}
              </div>
            {/if}
          </section>
        </div>
      {/if}
    </main>
  </div>
</div>
