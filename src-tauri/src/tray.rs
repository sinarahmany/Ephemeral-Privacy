use crate::decorrelator::DecorrelatorEngine;
use crate::panic::execute_panic_killswitch;
use crate::proxy::sys_proxy::disable_system_proxy;
use crate::state::AppState;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

pub struct TrayController {
    chaff: CheckMenuItem<Wry>,
    sni: CheckMenuItem<Wry>,
    odoh: CheckMenuItem<Wry>,
    webrtc: CheckMenuItem<Wry>,
    sentinel: CheckMenuItem<Wry>,
}

impl TrayController {
    /// Synchronizes menu bar checkmarks with the shared `AppState`.
    pub fn sync_with_state(&self, state: &AppState) {
        let _ = self
            .chaff
            .set_checked(state.chaff_enabled.load(Ordering::Relaxed));
        let _ = self
            .sni
            .set_checked(state.sni_fragmentation.load(Ordering::Relaxed));
        let _ = self
            .odoh
            .set_checked(state.odoh_enabled.load(Ordering::Relaxed));
        let _ = self
            .webrtc
            .set_checked(state.webrtc_shield.load(Ordering::Relaxed));
        let _ = self
            .sentinel
            .set_checked(state.hardware_sentinel_enabled.load(Ordering::Relaxed));
    }
}

fn show_main_window(app: &AppHandle<Wry>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Initializes the macOS/Desktop Menu Bar Tray Companion and returns a controller
/// to keep checkmarks synced with dashboard toggles.
pub fn setup_tray(
    app: &AppHandle<Wry>,
    state: Arc<AppState>,
    decorrelator: Arc<DecorrelatorEngine>,
) -> tauri::Result<TrayController> {
    let open_dashboard =
        MenuItem::with_id(app, "open_dashboard", "Open Privacy Dashboard", true, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;

    let chaff = CheckMenuItem::with_id(
        app,
        "toggle_chaff",
        "Decoy Traffic Camouflage",
        true,
        state.chaff_enabled.load(Ordering::Relaxed),
        None::<&str>,
    )?;
    let sni = CheckMenuItem::with_id(
        app,
        "toggle_sni",
        "Hide Visited Domains (SNI Split)",
        true,
        state.sni_fragmentation.load(Ordering::Relaxed),
        None::<&str>,
    )?;
    let odoh = CheckMenuItem::with_id(
        app,
        "toggle_odoh",
        "Oblivious DoH Relay (RFC 9230)",
        true,
        state.odoh_enabled.load(Ordering::Relaxed),
        None::<&str>,
    )?;
    let webrtc = CheckMenuItem::with_id(
        app,
        "toggle_webrtc",
        "WebRTC IP Leak Shield",
        true,
        state.webrtc_shield.load(Ordering::Relaxed),
        None::<&str>,
    )?;
    let sentinel = CheckMenuItem::with_id(
        app,
        "toggle_sentinel",
        "Camera & Mic Watchdog",
        true,
        state.hardware_sentinel_enabled.load(Ordering::Relaxed),
        None::<&str>,
    )?;

    let sep2 = PredefinedMenuItem::separator(app)?;
    let decoy_burst =
        MenuItem::with_id(app, "decoy_burst", "Send Decoy Burst Now", true, None::<&str>)?;
    let sep3 = PredefinedMenuItem::separator(app)?;
    let panic_reset =
        MenuItem::with_id(app, "panic_reset", "Emergency Reset (Panic)", true, None::<&str>)?;
    let quit_app =
        MenuItem::with_id(app, "quit_app", "Quit Ephemeral Privacy", true, None::<&str>)?;

    let menu = Menu::with_items(
        app,
        &[
            &open_dashboard,
            &sep1,
            &chaff,
            &sni,
            &odoh,
            &webrtc,
            &sentinel,
            &sep2,
            &decoy_burst,
            &sep3,
            &panic_reset,
            &quit_app,
        ],
    )?;

    let controller = TrayController {
        chaff: chaff.clone(),
        sni: sni.clone(),
        odoh: odoh.clone(),
        webrtc: webrtc.clone(),
        sentinel: sentinel.clone(),
    };

    let mut builder = TrayIconBuilder::with_id("ephemeral-tray")
        .menu(&menu)
        .tooltip("Ephemeral Privacy Suite — Shield Active")
        .show_menu_on_left_click(true)
        .icon_as_template(false);

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }

    let state_for_menu = state.clone();
    let deco_for_menu = decorrelator.clone();
    let chaff_item = chaff;
    let sni_item = sni;
    let odoh_item = odoh;
    let webrtc_item = webrtc;
    let sentinel_item = sentinel;

    builder
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            } else if let TrayIconEvent::Click {
                button: MouseButton::Right,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .on_menu_event(move |app, event| {
            let state = state_for_menu.clone();
            let deco = deco_for_menu.clone();
            match event.id.as_ref() {
                "open_dashboard" => {
                    show_main_window(app);
                }
                "toggle_chaff" => {
                    let next = !state.chaff_enabled.load(Ordering::Relaxed);
                    state.chaff_enabled.store(next, Ordering::Relaxed);
                    let _ = chaff_item.set_checked(next);
                    let _ = app.emit("privacy-state-changed", ());
                }
                "toggle_sni" => {
                    let next = !state.sni_fragmentation.load(Ordering::Relaxed);
                    state.sni_fragmentation.store(next, Ordering::Relaxed);
                    let _ = sni_item.set_checked(next);
                    let _ = app.emit("privacy-state-changed", ());
                }
                "toggle_odoh" => {
                    let next = !state.odoh_enabled.load(Ordering::Relaxed);
                    state.odoh_enabled.store(next, Ordering::Relaxed);
                    let _ = odoh_item.set_checked(next);
                    let _ = app.emit("privacy-state-changed", ());
                }
                "toggle_webrtc" => {
                    let next = !state.webrtc_shield.load(Ordering::Relaxed);
                    state.webrtc_shield.store(next, Ordering::Relaxed);
                    let _ = webrtc_item.set_checked(next);
                    let _ = app.emit("privacy-state-changed", ());
                }
                "toggle_sentinel" => {
                    let next = !state.hardware_sentinel_enabled.load(Ordering::Relaxed);
                    state.hardware_sentinel_enabled.store(next, Ordering::Relaxed);
                    let _ = sentinel_item.set_checked(next);
                    let _ = app.emit("privacy-state-changed", ());
                }
                "decoy_burst" => {
                    deco.trigger_chaff_burst("TRAY_MANUAL", "tray.decoy.trigger");
                    let s = state.clone();
                    tauri::async_runtime::spawn(async move {
                        s.log_event(
                            "DNS_CHAFF",
                            "Tray Decoy Burst Dispatched",
                            "Triggered manually from Menu Bar companion.",
                            "tray.decoy.trigger",
                        )
                        .await;
                    });
                    let _ = app.emit("privacy-state-changed", ());
                }
                "panic_reset" => {
                    let s = state.clone();
                    let app_handle = app.clone();
                    tauri::async_runtime::spawn(async move {
                        let _ = execute_panic_killswitch(s).await;
                        let _ = app_handle.emit("privacy-state-changed", ());
                    });
                }
                "quit_app" => {
                    println!("[SHUTDOWN] Tray quit requested, restoring direct OS network...");
                    let _ = disable_system_proxy();
                    app.exit(0);
                }
                _ => {}
            }
        })
        .build(app)?;

    Ok(controller)
}
