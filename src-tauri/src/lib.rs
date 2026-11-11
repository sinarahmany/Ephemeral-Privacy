pub mod decorrelator;
pub mod dns;
pub mod panic;
pub mod privacy;
pub mod proxy;
pub mod state;
pub mod tray;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::doh_pool::DohPool;
use crate::dns::DnsServer;
use crate::panic::execute_panic_killswitch;
use crate::privacy::{
    get_telemetry_profiles, probe_hardware_state, redact_pii, restore_pii, run_full_privacy_audit,
    start_clipboard_monitor, start_hardware_sentinel, HardwareStatus, OsTelemetryItem,
    PrivacyAuditReport, RedactionResult,
};
use crate::proxy::sys_proxy::{
    disable_system_proxy, enable_system_proxy, is_system_proxy_active,
};
use crate::proxy::ProxyServer;
use crate::state::{AppState, ChaffIntensity, PrivacyEvent, PrivacyMetrics};
use crate::tray::{setup_tray, TrayController};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tauri::{Emitter, Manager, State};

pub struct ManagedTray(pub Mutex<Option<TrayController>>);

#[derive(Serialize, Deserialize)]
pub struct AppConfigStatus {
    pub proxy_enabled: bool,
    pub dns_enabled: bool,
    pub chaff_enabled: bool,
    pub sni_fragmentation: bool,
    pub clipboard_cleaner: bool,
    pub pii_redactor: bool,
    pub odoh_enabled: bool,
    pub webrtc_shield: bool,
    pub ja3_shuffle: bool,
    pub hardware_sentinel_enabled: bool,
    pub minimize_to_tray: bool,
    pub chaff_intensity: String,
    pub upstream_resolver: String,
    pub os_proxy_active: bool,
}

#[tauri::command]
async fn get_privacy_status(state: State<'_, Arc<AppState>>) -> Result<AppConfigStatus, String> {
    let intensity_str = match *state.chaff_intensity.read().await {
        ChaffIntensity::Ghost => "Ghost",
        ChaffIntensity::Smokescreen => "Smokescreen",
        ChaffIntensity::HeavyFog => "HeavyFog",
    };
    let resolver_str = state.upstream_resolver.read().await.clone();
    let os_proxy_active = tokio::task::spawn_blocking(|| is_system_proxy_active(1080))
        .await
        .unwrap_or(false);

    Ok(AppConfigStatus {
        proxy_enabled: state.proxy_enabled.load(Ordering::Relaxed),
        dns_enabled: state.dns_enabled.load(Ordering::Relaxed),
        chaff_enabled: state.chaff_enabled.load(Ordering::Relaxed),
        sni_fragmentation: state.sni_fragmentation.load(Ordering::Relaxed),
        clipboard_cleaner: state.clipboard_cleaner.load(Ordering::Relaxed),
        pii_redactor: state.pii_redactor.load(Ordering::Relaxed),
        odoh_enabled: state.odoh_enabled.load(Ordering::Relaxed),
        webrtc_shield: state.webrtc_shield.load(Ordering::Relaxed),
        ja3_shuffle: state.ja3_shuffle.load(Ordering::Relaxed),
        hardware_sentinel_enabled: state.hardware_sentinel_enabled.load(Ordering::Relaxed),
        minimize_to_tray: state.minimize_to_tray.load(Ordering::Relaxed),
        chaff_intensity: intensity_str.to_string(),
        upstream_resolver: resolver_str,
        os_proxy_active,
    })
}

#[tauri::command]
async fn get_privacy_metrics(state: State<'_, Arc<AppState>>) -> Result<PrivacyMetrics, String> {
    Ok(state.get_metrics().await)
}

#[tauri::command]
async fn get_recent_events(state: State<'_, Arc<AppState>>) -> Result<Vec<PrivacyEvent>, String> {
    let events = state.recent_events.read().await;
    Ok(events.iter().cloned().collect())
}

#[tauri::command]
async fn toggle_feature(
    feature: String,
    enabled: bool,
    state: State<'_, Arc<AppState>>,
    tray: State<'_, Arc<ManagedTray>>,
) -> Result<(), String> {
    match feature.as_str() {
        "proxy" => {
            state.proxy_enabled.store(enabled, Ordering::Relaxed);
            if enabled {
                let _ = enable_system_proxy(1080);
            } else {
                let _ = disable_system_proxy();
            }
        }
        "dns" => state.dns_enabled.store(enabled, Ordering::Relaxed),
        "chaff" => state.chaff_enabled.store(enabled, Ordering::Relaxed),
        "sni" => state.sni_fragmentation.store(enabled, Ordering::Relaxed),
        "clipboard" => state.clipboard_cleaner.store(enabled, Ordering::Relaxed),
        "pii" => state.pii_redactor.store(enabled, Ordering::Relaxed),
        "odoh" => state.odoh_enabled.store(enabled, Ordering::Relaxed),
        "webrtc" => state.webrtc_shield.store(enabled, Ordering::Relaxed),
        "ja3" => state.ja3_shuffle.store(enabled, Ordering::Relaxed),
        "sentinel" => state
            .hardware_sentinel_enabled
            .store(enabled, Ordering::Relaxed),
        "minimize_to_tray" => state.minimize_to_tray.store(enabled, Ordering::Relaxed),
        _ => return Err(format!("Unknown feature: {}", feature)),
    }

    if let Ok(guard) = tray.0.lock() {
        if let Some(ref ctrl) = *guard {
            ctrl.sync_with_state(&state);
        }
    }

    state
        .log_event(
            "CONFIG_CHANGE",
            &format!("Module '{}' toggled to {}", feature, enabled),
            "User updated privacy module settings.",
            "localhost",
        )
        .await;

    Ok(())
}

#[tauri::command]
async fn set_chaff_intensity(
    intensity: String,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    let val = match intensity.to_ascii_lowercase().as_str() {
        "ghost" => ChaffIntensity::Ghost,
        "smokescreen" => ChaffIntensity::Smokescreen,
        "heavyfog" | "heavy_fog" => ChaffIntensity::HeavyFog,
        _ => return Err("Invalid chaff intensity".into()),
    };

    {
        let mut guard = state.chaff_intensity.write().await;
        *guard = val;
    }

    state
        .log_event(
            "CHAFF_CONFIG",
            &format!("Chaff Engine Intensity set to {}", intensity),
            "Adjusted Poisson delay distribution and decoy density.",
            "localhost",
        )
        .await;

    Ok(())
}

#[tauri::command]
async fn reassert_system_proxy(state: State<'_, Arc<AppState>>) -> Result<bool, String> {
    if state.proxy_enabled.load(Ordering::Relaxed) {
        enable_system_proxy(1080)?;
        state
            .log_event(
                "SYSTEM_PROXY_ASSERTED",
                "OS Proxy Routing Re-asserted",
                "Ensured system proxy is actively routing network traffic through 127.0.0.1:1080",
                "127.0.0.1",
            )
            .await;
        Ok(true)
    } else {
        Ok(false)
    }
}

#[tauri::command]
async fn trigger_manual_chaff_burst(
    state: State<'_, Arc<AppState>>,
    decorrelator: State<'_, Arc<DecorrelatorEngine>>,
) -> Result<bool, String> {
    if !state.chaff_enabled.load(Ordering::Relaxed) {
        return Ok(false);
    }
    decorrelator.trigger_chaff_burst("MANUAL", "manual.chaff.trigger");
    state
        .log_event(
            "DNS_CHAFF",
            "Manual Chaff Smokescreen Triggered",
            "Dispatched synthetic query cluster across rotated DoH resolvers.",
            "manual.chaff.trigger",
        )
        .await;
    Ok(true)
}

#[tauri::command]
async fn trigger_panic(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    tray: State<'_, Arc<ManagedTray>>,
) -> Result<String, String> {
    let msg = execute_panic_killswitch(state.inner().clone()).await?;
    if let Ok(guard) = tray.0.lock() {
        if let Some(ref ctrl) = *guard {
            ctrl.sync_with_state(&state);
        }
    }
    let _ = app.emit("privacy-state-changed", ());
    Ok(msg)
}

#[tauri::command]
fn sanitize_url_input(raw: String) -> Option<String> {
    crate::privacy::clipboard::sanitize_url(&raw)
}

#[tauri::command]
fn redact_pii_prompt(prompt: String) -> RedactionResult {
    redact_pii(&prompt)
}

#[tauri::command]
fn restore_pii_prompt(prompt: String, token_map: HashMap<String, String>) -> String {
    restore_pii(&prompt, &token_map)
}

#[tauri::command]
fn get_os_telemetry_list() -> Vec<OsTelemetryItem> {
    get_telemetry_profiles()
}

#[tauri::command]
async fn run_privacy_audit(
    state: State<'_, Arc<AppState>>,
    doh_pool: State<'_, DohPool>,
) -> Result<PrivacyAuditReport, String> {
    Ok(run_full_privacy_audit(state.inner().clone(), doh_pool.inner().clone()).await)
}

#[tauri::command]
async fn get_hardware_status() -> Result<HardwareStatus, String> {
    tokio::task::spawn_blocking(probe_hardware_state)
        .await
        .map_err(|e| format!("Hardware probe failed: {}", e))
}

extern "C" fn atexit_cleanup() {
    let _ = disable_system_proxy();
}

pub fn run() {
    // 1. Register atexit handler so proxy is always restored on any process exit
    unsafe {
        libc::atexit(atexit_cleanup);
    }

    // 2. Register panic hook to restore direct connection on panic
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = disable_system_proxy();
        default_hook(panic_info);
    }));

    let app_state = Arc::new(AppState::new());
    let doh_pool = DohPool::new();
    let decorrelator = Arc::new(DecorrelatorEngine::new(app_state.clone(), doh_pool.clone()));
    let managed_tray = Arc::new(ManagedTray(Mutex::new(None)));

    let state_for_setup = app_state.clone();
    let decorrelator_for_setup = decorrelator.clone();
    let doh_pool_for_manage = doh_pool.clone();
    let tray_for_setup = managed_tray.clone();
    let state_for_window = app_state.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state_for_setup)
        .manage(decorrelator_for_setup)
        .manage(doh_pool_for_manage)
        .manage(managed_tray)
        .on_window_event(move |window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if state_for_window.minimize_to_tray.load(Ordering::Relaxed) {
                    println!("[TRAY] Window close requested — hiding dashboard to menu bar tray (protection remains active).");
                    api.prevent_close();
                    let _ = window.hide();
                } else {
                    println!("[SHUTDOWN] Window close requested, restoring direct connection...");
                    let _ = disable_system_proxy();
                    window.app_handle().exit(0);
                }
            }
            if let tauri::WindowEvent::Destroyed = event {
                let _ = disable_system_proxy();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_privacy_status,
            get_privacy_metrics,
            get_recent_events,
            toggle_feature,
            reassert_system_proxy,
            set_chaff_intensity,
            trigger_manual_chaff_burst,
            trigger_panic,
            sanitize_url_input,
            redact_pii_prompt,
            restore_pii_prompt,
            get_os_telemetry_list,
            run_privacy_audit,
            get_hardware_status
        ])
        .setup(move |app| {
            // Initialize Menu Bar / System Tray Companion
            match setup_tray(app.handle(), app_state.clone(), decorrelator.clone()) {
                Ok(ctrl) => {
                    if let Ok(mut guard) = tray_for_setup.0.lock() {
                        *guard = Some(ctrl);
                    }
                }
                Err(e) => {
                    eprintln!("Warning: could not initialize tray icon: {}", e);
                }
            }

            let dns_server = DnsServer::new(
                app_state.clone(),
                doh_pool.clone(),
                decorrelator.clone(),
            );
            let proxy_server = ProxyServer::new(
                app_state.clone(),
                decorrelator.clone(),
                doh_pool.clone(),
            );

            // Spawn Background DNS Server with auto-port fallback (5300, 1053, etc.)
            tauri::async_runtime::spawn(async move {
                if let Err(e) = dns_server.run_auto().await {
                    eprintln!("DNS Server error: {}", e);
                }
            });

            // Spawn Background Proxy Server on 127.0.0.1:1080 within Tauri async runtime
            let proxy_bind: SocketAddr = "127.0.0.1:1080".parse().unwrap();
            tauri::async_runtime::spawn(async move {
                if let Err(e) = proxy_server.run(proxy_bind).await {
                    eprintln!("Proxy Server error: {}", e);
                }
            });

            // Automatically configure OS system proxy on startup if enabled
            if app_state.proxy_enabled.load(Ordering::Relaxed) {
                if let Err(e) = enable_system_proxy(1080) {
                    eprintln!("Warning: could not set OS system proxy on startup: {}", e);
                } else {
                    println!("[SYSTEM] Configured OS proxy to 127.0.0.1:1080");
                }
            }

            // Start background clipboard monitor (uses thread::spawn internally)
            start_clipboard_monitor(app_state.clone());

            // Start Hardware Snooping Sentinel (Camera & Microphone watchdog)
            start_hardware_sentinel(app_state.clone());

            // Sync community ad/tracker blocklists strictly into volatile RAM
            crate::dns::sinkhole::spawn_blocklist_sync(app_state.clone());

            // Log startup
            let state_clone = app_state.clone();
            tauri::async_runtime::spawn(async move {
                state_clone
                    .log_event(
                        "SYSTEM_STARTUP",
                        "Ephemeral Privacy Suite Initialized",
                        "Proxy :1080, ODoH Relay DNS :5300, WebRTC Shield & Hardware Watchdog active.",
                        "127.0.0.1",
                    )
                    .await;
            });

            async fn graceful_signal_shutdown(app: tauri::AppHandle) {
                let _ = tokio::task::spawn_blocking(disable_system_proxy).await;
                app.exit(0);
                // Ensure prompt termination even if an idle headless/webview loop refuses to pump Exit
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                std::process::exit(0);
            }

            // Register graceful termination cleanup to ensure proxy is reset and process exits cleanly on signals
            let sig_int_app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    graceful_signal_shutdown(sig_int_app).await;
                }
            });

            #[cfg(unix)]
            {
                let sig_term_app = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    use tokio::signal::unix::{signal, SignalKind};
                    if let Ok(mut term) = signal(SignalKind::terminate()) {
                        term.recv().await;
                        graceful_signal_shutdown(sig_term_app).await;
                    }
                });

                let sig_hup_app = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    use tokio::signal::unix::{signal, SignalKind};
                    if let Ok(mut hup) = signal(SignalKind::hangup()) {
                        hup.recv().await;
                        graceful_signal_shutdown(sig_hup_app).await;
                    }
                });
            }

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|app_handle, event| match event {
            #[cfg(target_os = "macos")]
            tauri::RunEvent::Reopen { .. } => {
                if let Some(window) = app_handle.get_webview_window("main") {
                    if !window.is_visible().unwrap_or(false)
                        || window.is_minimized().unwrap_or(false)
                    {
                        let _ = window.unminimize();
                        let _ = window.show();
                    }
                    let _ = window.set_focus();
                }
            }
            tauri::RunEvent::ExitRequested { .. } | tauri::RunEvent::Exit => {
                let _ = disable_system_proxy();
                println!("[SYSTEM] Reset OS proxy to direct connection on exit.");
            }
            _ => {
                let _ = app_handle;
            }
        });
}
