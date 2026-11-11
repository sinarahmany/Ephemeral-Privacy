use crate::state::AppState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareStatus {
    pub camera_active: bool,
    pub mic_active: bool,
    pub camera_apps: Vec<String>,
    pub mic_apps: Vec<String>,
    pub platform_method: String,
}

/// Probes current hardware camera and microphone activation state without requesting
/// OS capture permissions (zero macOS TCC prompt).
pub fn probe_hardware_state() -> HardwareStatus {
    #[cfg(target_os = "macos")]
    {
        probe_macos_hardware()
    }
    #[cfg(target_os = "linux")]
    {
        probe_linux_hardware()
    }
    #[cfg(target_os = "windows")]
    {
        probe_windows_hardware()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        HardwareStatus {
            camera_active: false,
            mic_active: false,
            camera_apps: Vec::new(),
            mic_apps: Vec::new(),
            platform_method: "Unsupported OS".to_string(),
        }
    }
}

/// Spawns the background Hardware Snooping Sentinel polling every 1.5 seconds.
pub fn start_hardware_sentinel(state: Arc<AppState>) {
    tauri::async_runtime::spawn(async move {
        let mut prev_cam = false;
        let mut prev_mic = false;

        loop {
            tokio::time::sleep(Duration::from_millis(1500)).await;

            if !state.hardware_sentinel_enabled.load(Ordering::Relaxed) {
                if prev_cam || prev_mic {
                    state.camera_active.store(false, Ordering::Relaxed);
                    state.mic_active.store(false, Ordering::Relaxed);
                    *state.camera_apps.write().await = Vec::new();
                    *state.mic_apps.write().await = Vec::new();
                    prev_cam = false;
                    prev_mic = false;
                }
                continue;
            }

            let status = match tokio::task::spawn_blocking(probe_hardware_state).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            state
                .camera_active
                .store(status.camera_active, Ordering::Relaxed);
            state.mic_active.store(status.mic_active, Ordering::Relaxed);
            {
                let mut g = state.camera_apps.write().await;
                *g = status.camera_apps.clone();
            }
            {
                let mut g = state.mic_apps.write().await;
                *g = status.mic_apps.clone();
            }

            if status.camera_active && !prev_cam {
                state.hardware_alerts_count.fetch_add(1, Ordering::Relaxed);
                let apps = if status.camera_apps.is_empty() {
                    "Unknown Video Client".to_string()
                } else {
                    status.camera_apps.join(", ")
                };
                state
                    .log_event(
                        "HARDWARE_ALERT",
                        "Camera Sensor Activated",
                        &format!("Webcam stream detected ({}) — Method: {}", apps, status.platform_method),
                        &apps,
                    )
                    .await;
            } else if !status.camera_active && prev_cam {
                state
                    .log_event(
                        "HARDWARE_CLEAR",
                        "Camera Sensor Deactivated",
                        "Webcam video stream ended; sensor returned to idle.",
                        "hardware.camera",
                    )
                    .await;
            }

            if status.mic_active && !prev_mic {
                state.hardware_alerts_count.fetch_add(1, Ordering::Relaxed);
                let apps = if status.mic_apps.is_empty() {
                    "Unknown Audio Input Client".to_string()
                } else {
                    status.mic_apps.join(", ")
                };
                state
                    .log_event(
                        "HARDWARE_ALERT",
                        "Microphone Input Activated",
                        &format!("Live microphone capture detected ({}) — Method: {}", apps, status.platform_method),
                        &apps,
                    )
                    .await;
            } else if !status.mic_active && prev_mic {
                state
                    .log_event(
                        "HARDWARE_CLEAR",
                        "Microphone Input Deactivated",
                        "Microphone input stream stopped; sensor returned to idle.",
                        "hardware.microphone",
                    )
                    .await;
            }

            prev_cam = status.camera_active;
            prev_mic = status.mic_active;
        }
    });
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::ffi::c_void;
    use std::process::Command;
    use std::ptr;

    #[repr(C)]
    struct AudioObjectPropertyAddress {
        m_selector: u32,
        m_scope: u32,
        m_element: u32,
    }

    #[repr(C)]
    struct CMIOObjectPropertyAddress {
        m_selector: u32,
        m_scope: u32,
        m_element: u32,
    }

    #[link(name = "CoreAudio", kind = "framework")]
    unsafe extern "C" {
        fn AudioObjectGetPropertyDataSize(
            in_object_id: u32,
            in_address: *const AudioObjectPropertyAddress,
            in_qualifier_data_size: u32,
            in_qualifier_data: *const c_void,
            out_data_size: *mut u32,
        ) -> i32;

        fn AudioObjectGetPropertyData(
            in_object_id: u32,
            in_address: *const AudioObjectPropertyAddress,
            in_qualifier_data_size: u32,
            in_qualifier_data: *const c_void,
            io_data_size: *mut u32,
            out_data: *mut c_void,
        ) -> i32;
    }

    #[link(name = "CoreMediaIO", kind = "framework")]
    unsafe extern "C" {
        fn CMIOObjectGetPropertyDataSize(
            object_id: u32,
            address: *const CMIOObjectPropertyAddress,
            qualifier_data_size: u32,
            qualifier_data: *const c_void,
            data_size: *mut u32,
        ) -> i32;

        fn CMIOObjectGetPropertyData(
            object_id: u32,
            address: *const CMIOObjectPropertyAddress,
            qualifier_data_size: u32,
            qualifier_data: *const c_void,
            data_size: u32,
            data_used: *mut u32,
            data: *mut c_void,
        ) -> i32;
    }

    const fn fourcc(bytes: &[u8; 4]) -> u32 {
        u32::from_be_bytes(*bytes)
    }

    const SYSTEM_OBJECT_ID: u32 = 1;
    const PROP_DEVICES: u32 = fourcc(b"dev#");
    const PROP_STREAMS: u32 = fourcc(b"stm#");
    const PROP_IS_RUNNING_SOMEWHERE: u32 = fourcc(b"gone");
    const SCOPE_GLOBAL: u32 = fourcc(b"glob");
    const SCOPE_INPUT: u32 = fourcc(b"inpt");
    const ELEMENT_MAIN: u32 = 0;

    fn is_any_audio_input_running() -> bool {
        unsafe {
            let dev_addr = AudioObjectPropertyAddress {
                m_selector: PROP_DEVICES,
                m_scope: SCOPE_GLOBAL,
                m_element: ELEMENT_MAIN,
            };
            let mut data_size: u32 = 0;
            let status = AudioObjectGetPropertyDataSize(
                SYSTEM_OBJECT_ID,
                &dev_addr,
                0,
                ptr::null(),
                &mut data_size,
            );
            if status != 0 || data_size == 0 {
                return false;
            }

            let count = (data_size as usize) / std::mem::size_of::<u32>();
            let mut devices = vec![0u32; count];
            let status = AudioObjectGetPropertyData(
                SYSTEM_OBJECT_ID,
                &dev_addr,
                0,
                ptr::null(),
                &mut data_size,
                devices.as_mut_ptr() as *mut c_void,
            );
            if status != 0 {
                return false;
            }

            let actual_count = (data_size as usize) / std::mem::size_of::<u32>();
            for &device_id in devices.iter().take(actual_count) {
                // Only examine devices that actually expose at least one audio INPUT stream
                let stream_addr = AudioObjectPropertyAddress {
                    m_selector: PROP_STREAMS,
                    m_scope: SCOPE_INPUT,
                    m_element: ELEMENT_MAIN,
                };
                let mut stream_size: u32 = 0;
                if AudioObjectGetPropertyDataSize(
                    device_id,
                    &stream_addr,
                    0,
                    ptr::null(),
                    &mut stream_size,
                ) != 0
                    || stream_size < std::mem::size_of::<u32>() as u32
                {
                    continue;
                }

                let run_addr = AudioObjectPropertyAddress {
                    m_selector: PROP_IS_RUNNING_SOMEWHERE,
                    m_scope: SCOPE_GLOBAL,
                    m_element: ELEMENT_MAIN,
                };
                let mut is_running: u32 = 0;
                let mut run_size: u32 = std::mem::size_of::<u32>() as u32;
                if AudioObjectGetPropertyData(
                    device_id,
                    &run_addr,
                    0,
                    ptr::null(),
                    &mut run_size,
                    &mut is_running as *mut u32 as *mut c_void,
                ) == 0
                    && is_running != 0
                {
                    return true;
                }
            }
            false
        }
    }

    fn is_any_cmio_camera_running() -> bool {
        unsafe {
            let dev_addr = CMIOObjectPropertyAddress {
                m_selector: PROP_DEVICES,
                m_scope: SCOPE_GLOBAL,
                m_element: ELEMENT_MAIN,
            };
            let mut data_size: u32 = 0;
            if CMIOObjectGetPropertyDataSize(
                SYSTEM_OBJECT_ID,
                &dev_addr,
                0,
                ptr::null(),
                &mut data_size,
            ) != 0
                || data_size == 0
            {
                return false;
            }

            let count = (data_size as usize) / std::mem::size_of::<u32>();
            let mut devices = vec![0u32; count];
            let mut data_used: u32 = 0;
            if CMIOObjectGetPropertyData(
                SYSTEM_OBJECT_ID,
                &dev_addr,
                0,
                ptr::null(),
                data_size,
                &mut data_used,
                devices.as_mut_ptr() as *mut c_void,
            ) != 0
            {
                return false;
            }

            let actual_count = (data_used as usize) / std::mem::size_of::<u32>();
            for &device_id in devices.iter().take(actual_count) {
                let stream_addr = CMIOObjectPropertyAddress {
                    m_selector: PROP_STREAMS,
                    m_scope: SCOPE_INPUT,
                    m_element: ELEMENT_MAIN,
                };
                let mut stream_size: u32 = 0;
                if CMIOObjectGetPropertyDataSize(
                    device_id,
                    &stream_addr,
                    0,
                    ptr::null(),
                    &mut stream_size,
                ) != 0
                    || stream_size < std::mem::size_of::<u32>() as u32
                {
                    continue;
                }

                let run_addr = CMIOObjectPropertyAddress {
                    m_selector: PROP_IS_RUNNING_SOMEWHERE,
                    m_scope: SCOPE_GLOBAL,
                    m_element: ELEMENT_MAIN,
                };
                let mut is_running: u32 = 0;
                let mut run_used: u32 = 0;
                if CMIOObjectGetPropertyData(
                    device_id,
                    &run_addr,
                    0,
                    ptr::null(),
                    std::mem::size_of::<u32>() as u32,
                    &mut run_used,
                    &mut is_running as *mut u32 as *mut c_void,
                ) == 0
                    && is_running != 0
                {
                    return true;
                }
            }
            false
        }
    }

    fn is_apple_silicon_cam_active_ioreg() -> bool {
        for svc in ["AppleH13CamIn", "AppleH14CamIn", "AppleH15CamIn", "AppleH16CamIn"] {
            if let Ok(out) = Command::new("ioreg").args(["-rn", svc]).output() {
                let text = String::from_utf8_lossy(&out.stdout);
                if text.contains("\"FrontCameraActive\" = Yes")
                    || text.contains("\"FrontCameraStreaming\" = Yes")
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn resolve_pid_app_name(pid: &str) -> Option<String> {
        let out = Command::new("ps")
            .args(["-p", pid, "-o", "comm="])
            .output()
            .ok()?;
        let path = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if path.is_empty() {
            return None;
        }
        // Prefer enclosing `.app` bundle display name if inside a macOS bundle
        for segment in path.split('/') {
            if let Some(app_name) = segment.strip_suffix(".app") {
                if !app_name.is_empty() {
                    return Some(app_name.to_string());
                }
            }
        }
        path.rsplit('/').next().map(|s| s.to_string())
    }

    pub fn parse_pmset_assertions(text: &str) -> (Vec<String>, Vec<String>) {
        let mut mic_pids = BTreeSet::new();
        let mut cam_pids = BTreeSet::new();

        let mut current_owner: Option<&str> = None;
        let mut pending_pid: Option<&str> = None;
        let mut current_has_audio_in = false;
        let mut current_has_camera_hint = false;

        let flush = |owner: Option<&str>,
                     pid: Option<&str>,
                     audio_in: bool,
                     cam_hint: bool,
                     mic_pids: &mut BTreeSet<String>,
                     cam_pids: &mut BTreeSet<String>| {
            if audio_in {
                if let Some(p) = pid {
                    mic_pids.insert(p.to_string());
                } else if let Some(o) = owner {
                    mic_pids.insert(format!("name:{}", o));
                }
            }
            if cam_hint {
                if let Some(p) = pid {
                    cam_pids.insert(p.to_string());
                } else if let Some(o) = owner {
                    cam_pids.insert(format!("name:{}", o));
                }
            }
        };

        for raw_line in text.lines() {
            let trimmed = raw_line.trim();
            if trimmed.starts_with("pid ") {
                flush(
                    current_owner,
                    pending_pid,
                    current_has_audio_in,
                    current_has_camera_hint,
                    &mut mic_pids,
                    &mut cam_pids,
                );
                current_owner = None;
                pending_pid = None;
                current_has_audio_in = false;
                current_has_camera_hint = false;

                // Example: `pid 434(coreaudiod): [...] ... named: "..."`
                if let (Some(open), Some(close)) = (trimmed.find('('), trimmed.find(')')) {
                    if close > open + 1 {
                        let owner = &trimmed[open + 1..close];
                        current_owner = Some(owner);
                        let lower = trimmed.to_ascii_lowercase();
                        if lower.contains("camera")
                            || lower.contains("cameracaptured")
                            || lower.contains("vdcassistant")
                            || lower.contains("avcapture")
                        {
                            current_has_camera_hint = true;
                        }
                    }
                }
            } else if let Some(rest) = trimmed.strip_prefix("Created for PID:") {
                let pid = rest.trim().trim_end_matches('.');
                if !pid.is_empty() && pid.chars().all(|c| c.is_ascii_digit()) {
                    pending_pid = Some(pid);
                }
            } else if trimmed.starts_with("Resources:") {
                let lower = trimmed.to_ascii_lowercase();
                if lower.contains("audio-in") {
                    current_has_audio_in = true;
                }
                if lower.contains("camera") || lower.contains("video-in") {
                    current_has_camera_hint = true;
                }
            }
        }
        flush(
            current_owner,
            pending_pid,
            current_has_audio_in,
            current_has_camera_hint,
            &mut mic_pids,
            &mut cam_pids,
        );

        let resolve_set = |entries: BTreeSet<String>| -> Vec<String> {
            let mut names = BTreeSet::new();
            for item in entries {
                if let Some(name) = item.strip_prefix("name:") {
                    names.insert(name.to_string());
                } else if let Some(resolved) = resolve_pid_app_name(&item) {
                    names.insert(resolved);
                } else {
                    names.insert(format!("PID {}", item));
                }
            }
            names.into_iter().collect()
        };

        (resolve_set(mic_pids), resolve_set(cam_pids))
    }

    pub fn probe_macos_hardware() -> HardwareStatus {
        let mic_active = is_any_audio_input_running();
        let cam_active = is_any_cmio_camera_running() || is_apple_silicon_cam_active_ioreg();

        let (mut mic_apps, mut camera_apps) = if mic_active || cam_active {
            Command::new("pmset")
                .args(["-g", "assertions"])
                .output()
                .ok()
                .map(|o| parse_pmset_assertions(&String::from_utf8_lossy(&o.stdout)))
                .unwrap_or_default()
        } else {
            (Vec::new(), Vec::new())
        };

        if mic_active && mic_apps.is_empty() {
            mic_apps.push("Active Audio Input Client".to_string());
        }
        if cam_active && camera_apps.is_empty() {
            camera_apps.push("Active Camera Stream Client".to_string());
        }

        HardwareStatus {
            camera_active: cam_active,
            mic_active,
            camera_apps,
            mic_apps,
            platform_method: "macOS CoreAudio + CoreMediaIO + IORegistry".to_string(),
        }
    }
}

#[cfg(target_os = "macos")]
use macos::probe_macos_hardware;

#[cfg(target_os = "linux")]
fn probe_linux_hardware() -> HardwareStatus {
    use std::fs;
    let mut mic_active = false;
    if let Ok(cards) = fs::read_dir("/proc/asound") {
        for card in cards.flatten() {
            let name = card.file_name().to_string_lossy().to_string();
            if !name.starts_with("card") {
                continue;
            }
            if let Ok(entries) = fs::read_dir(card.path()) {
                for sub in entries.flatten() {
                    let sname = sub.file_name().to_string_lossy().to_string();
                    if sname.starts_with("pcm") && sname.ends_with('c') {
                        if let Ok(subs) = fs::read_dir(sub.path()) {
                            for s in subs.flatten() {
                                let status_path = s.path().join("status");
                                if let Ok(content) = fs::read_to_string(status_path) {
                                    if content.contains("state: RUNNING") {
                                        mic_active = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    let mut cam_apps = BTreeSet::new();
    if let Ok(procs) = fs::read_dir("/proc") {
        for proc_entry in procs.flatten() {
            let pid_str = proc_entry.file_name().to_string_lossy().to_string();
            if !pid_str.chars().all(|c| c.is_ascii_digit()) {
                continue;
            }
            let fd_dir = proc_entry.path().join("fd");
            if let Ok(fds) = fs::read_dir(fd_dir) {
                for fd in fds.flatten() {
                    if let Ok(target) = fs::read_link(fd.path()) {
                        if target.to_string_lossy().starts_with("/dev/video") {
                            let comm = fs::read_to_string(proc_entry.path().join("comm"))
                                .unwrap_or_else(|_| format!("PID {}", pid_str))
                                .trim()
                                .to_string();
                            cam_apps.insert(comm);
                        }
                    }
                }
            }
        }
    }

    HardwareStatus {
        camera_active: !cam_apps.is_empty(),
        mic_active,
        camera_apps: cam_apps.into_iter().collect(),
        mic_apps: if mic_active {
            vec!["ALSA Capture Stream".to_string()]
        } else {
            Vec::new()
        },
        platform_method: "Linux ALSA + /proc/*/fd (/dev/video*)".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn probe_windows_hardware() -> HardwareStatus {
    use std::process::Command;

    fn query_consent_store(cap: &str) -> Vec<String> {
        let key = format!(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\{}",
            cap
        );
        let Ok(out) = Command::new("reg")
            .args(["query", &key, "/s", "/v", "LastUsedTimeStop"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&out.stdout);
        let mut active = BTreeSet::new();
        let mut current_app: Option<String> = None;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("HKEY_") {
                current_app = trimmed
                    .rsplit('\\')
                    .next()
                    .map(|s| s.replace('#', "\\"));
            } else if trimmed.contains("LastUsedTimeStop") && trimmed.ends_with("0x0") {
                if let Some(ref app) = current_app {
                    if app != "NonPackaged" {
                        let nice = app
                            .rsplit('\\')
                            .next()
                            .unwrap_or(app)
                            .to_string();
                        active.insert(nice);
                    }
                }
            }
        }
        active.into_iter().collect()
    }

    let camera_apps = query_consent_store("webcam");
    let mic_apps = query_consent_store("microphone");
    HardwareStatus {
        camera_active: !camera_apps.is_empty(),
        mic_active: !mic_apps.is_empty(),
        camera_apps,
        mic_apps,
        platform_method: "Windows CapabilityAccessManager ConsentStore".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hardware_probe_runs_safely_without_panic() {
        let start = std::time::Instant::now();
        let status = probe_hardware_state();
        let elapsed = start.elapsed();
        println!("Hardware probe took {:?}: {:?}", elapsed, status);
        assert!(!status.platform_method.is_empty());
        assert!(elapsed.as_secs() < 2);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_pmset_assertions_distinguishes_audio_in_from_audio_out() {
        let sample = r#"
Listed by owning process:
   pid 434(coreaudiod): [0x01] 00:01:00 PreventUserIdleSystemSleep named: "audio out"
	Created for PID: 999999.
	Resources: audio-out BuiltInHeadphoneOutputDevice
   pid 434(coreaudiod): [0x02] 00:00:05 PreventUserIdleSystemSleep named: "audio in"
	Created for PID: 888888.
	Resources: audio-in MacBookProMic
"#;
        let (mic_apps, _cam_apps) = macos::parse_pmset_assertions(sample);
        assert_eq!(mic_apps, vec!["PID 888888".to_string()]);
    }
}
