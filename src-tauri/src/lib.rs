pub mod decorrelator;
pub mod dns;
pub mod panic;
pub mod privacy;
pub mod proxy;
pub mod state;

use crate::decorrelator::DecorrelatorEngine;
use crate::dns::doh_pool::DohPool;
use crate::dns::DnsServer;
use crate::panic::execute_panic_killswitch;
use crate::privacy::{
    get_telemetry_profiles, redact_pii, restore_pii, start_clipboard_monitor, OsTelemetryItem,
    RedactionResult,
};
use crate::proxy::sys_proxy::{disable_system_proxy, enable_system_proxy};
use crate::proxy::ProxyServer;
use crate::state::{AppState, ChaffIntensity, PrivacyEvent, PrivacyMetrics};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::State;

#[derive(Serialize, Deserialize)]
pub struct AppConfigStatus {
    pub proxy_enabled: bool,
    pub dns_enabled: bool,
    pub chaff_enabled: bool,
    pub sni_fragmentation: bool,
    pub clipboard_cleaner: bool,
    pub pii_redactor: bool,
    pub chaff_intensity: String,
    pub upstream_resolver: String,
}

#[tauri::command]
async fn get_privacy_status(state: State<'_, Arc<AppState>>) -> Result<AppConfigStatus, String> {
    let intensity_str = match *state.chaff_intensity.read().await {
        ChaffIntensity::Ghost => "Ghost",
        ChaffIntensity::Smokescreen => "Smokescreen",
        ChaffIntensity::HeavyFog => "HeavyFog",
    };
    let resolver_str = state.upstream_resolver.read().await.clone();

    Ok(AppConfigStatus {
        proxy_enabled: state.proxy_enabled.load(Ordering::Relaxed),
        dns_enabled: state.dns_enabled.load(Ordering::Relaxed),
        chaff_enabled: state.chaff_enabled.load(Ordering::Relaxed),
        sni_fragmentation: state.sni_fragmentation.load(Ordering::Relaxed),
        clipboard_cleaner: state.clipboard_cleaner.load(Ordering::Relaxed),
        pii_redactor: state.pii_redactor.load(Ordering::Relaxed),
        chaff_intensity: intensity_str.to_string(),
        upstream_resolver: resolver_str,
    })
}

#[tauri::command]
async fn get_privacy_metrics(state: State<'_, Arc<AppState>>) -> Result<PrivacyMetrics, String> {
    Ok(state.get_metrics())
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
        _ => return Err(format!("Unknown feature: {}", feature)),
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
async fn trigger_manual_chaff_burst(
    state: State<'_, Arc<AppState>>,
    decorrelator: State<'_, Arc<DecorrelatorEngine>>,
) -> Result<(), String> {
    decorrelator.trigger_chaff_burst("MANUAL", "manual.chaff.trigger");
    state
        .log_event(
            "DNS_CHAFF",
            "Manual Chaff Smokescreen Triggered",
            "Dispatched synthetic query cluster across rotated DoH resolvers.",
            "manual.chaff.trigger",
        )
        .await;
    Ok(())
}

#[tauri::command]
async fn trigger_panic(state: State<'_, Arc<AppState>>) -> Result<String, String> {
    execute_panic_killswitch(state.inner().clone()).await
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

pub fn run() {
    let app_state = Arc::new(AppState::new());
    let doh_pool = DohPool::new();
    let decorrelator = Arc::new(DecorrelatorEngine::new(app_state.clone(), doh_pool.clone()));

    let state_for_setup = app_state.clone();
    let decorrelator_for_setup = decorrelator.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(state_for_setup)
        .manage(decorrelator_for_setup)
        .invoke_handler(tauri::generate_handler![
            get_privacy_status,
            get_privacy_metrics,
            get_recent_events,
            toggle_feature,
            set_chaff_intensity,
            trigger_manual_chaff_burst,
            trigger_panic,
            sanitize_url_input,
            redact_pii_prompt,
            restore_pii_prompt,
            get_os_telemetry_list
        ])
        .setup(move |_app| {
            let dns_server = DnsServer::new(
                app_state.clone(),
                doh_pool.clone(),
                decorrelator.clone(),
            );
            let proxy_server = ProxyServer::new(app_state.clone(), decorrelator.clone());

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

            // Log startup
            let state_clone = app_state.clone();
            tauri::async_runtime::spawn(async move {
                state_clone
                    .log_event(
                        "SYSTEM_STARTUP",
                        "Ephemeral Privacy Suite Initialized",
                        "SOCKS5 & HTTP Proxy active on :1080, DNS on :5300. Auto-configured OS routing.",
                        "127.0.0.1",
                    )
                    .await;
            });

            // Register graceful termination cleanup to ensure proxy is reset on exit
            tauri::async_runtime::spawn(async {
                if tokio::signal::ctrl_c().await.is_ok() {
                    let _ = disable_system_proxy();
                }
            });

            #[cfg(unix)]
            tauri::async_runtime::spawn(async {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut term) = signal(SignalKind::terminate()) {
                    term.recv().await;
                    let _ = disable_system_proxy();
                }
            });

            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building tauri application")
        .run(|_app_handle, event| {
            if let tauri::RunEvent::ExitRequested { .. } = event {
                let _ = disable_system_proxy();
                println!("[SYSTEM] Reset OS proxy to direct connection.");
            }
        });
}
