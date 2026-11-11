use crate::proxy::sys_proxy::disable_system_proxy;
use crate::state::AppState;
use std::process::Command;
use std::sync::Arc;

pub async fn execute_panic_killswitch(state: Arc<AppState>) -> Result<String, String> {
    // 1. Instantly unconfigure OS system proxy and sync UI toggle state
    state
        .proxy_enabled
        .store(false, std::sync::atomic::Ordering::Relaxed);
    let _ = disable_system_proxy();

    // 2. Clear OS DNS Cache
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("dscacheutil").arg("-flushcache").output();
        let _ = Command::new("killall")
            .arg("-HUP")
            .arg("mDNSResponder")
            .output();
    }

    #[cfg(target_os = "windows")]
    {
        let _ = Command::new("ipconfig").arg("/flushdns").output();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("resolvectl").arg("flush-caches").output();
    }

    // 3. Clear System Clipboard
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.clear();
    }

    // 4. Purge volatile in-memory log buffer
    {
        let mut events = state.recent_events.write().await;
        events.clear();
    }

    state
        .log_event(
            "PANIC_TRIGGERED",
            "Emergency Panic Switch Activated",
            "OS Proxy disabled, system DNS cache flushed, and clipboard sanitized.",
            "localhost",
        )
        .await;

    Ok("Panic killswitch activated: System network restored to direct connection and caches flushed.".into())
}
