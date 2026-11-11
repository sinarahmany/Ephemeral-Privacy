use sysproxy::Sysproxy;

const PROXY_BYPASS_DOMAINS: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "*.local",
    "192.168.0.0/16",
    "10.0.0.0/8",
];

#[cfg(target_os = "macos")]
fn list_macos_services() -> Vec<String> {
    let mut services = Vec::new();
    if let Ok(output) = std::process::Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
    {
        if let Ok(stdout) = std::str::from_utf8(&output.stdout) {
            for line in stdout.lines() {
                let service = line.trim();
                if service.is_empty()
                    || service.starts_with('*')
                    || service.contains("denotes that")
                {
                    continue;
                }
                services.push(service.to_string());
            }
        }
    }
    services
}

#[cfg(target_os = "macos")]
fn macos_service_has_active_ipv4(service: &str) -> bool {
    let Ok(output) = std::process::Command::new("networksetup")
        .args(["-getinfo", service])
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(ip) = trimmed.strip_prefix("IP address:") {
            let ip = ip.trim();
            if !ip.is_empty() && !ip.eq_ignore_ascii_case("none") && ip != "0.0.0.0" {
                return true;
            }
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn macos_configure_service_proxy(service: &str, port: u16) -> bool {
    let port_str = port.to_string();
    let ok_http = std::process::Command::new("networksetup")
        .args(["-setwebproxy", service, "127.0.0.1", &port_str])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let _ = std::process::Command::new("networksetup")
        .args(["-setwebproxystate", service, "on"])
        .output();
    let ok_https = std::process::Command::new("networksetup")
        .args(["-setsecurewebproxy", service, "127.0.0.1", &port_str])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let _ = std::process::Command::new("networksetup")
        .args(["-setsecurewebproxystate", service, "on"])
        .output();
    let _ = std::process::Command::new("networksetup")
        .args(["-setsocksfirewallproxy", service, "127.0.0.1", &port_str])
        .output();
    let _ = std::process::Command::new("networksetup")
        .args(["-setsocksfirewallproxystate", service, "on"])
        .output();

    let mut bypass_args = vec!["-setproxybypassdomains", service];
    bypass_args.extend(PROXY_BYPASS_DOMAINS.iter().copied());
    let _ = std::process::Command::new("networksetup")
        .args(&bypass_args)
        .output();

    ok_http || ok_https
}

pub fn enable_system_proxy(port: u16) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let services = list_macos_services();
        let mut active_targets: Vec<String> = services
            .iter()
            .filter(|svc| macos_service_has_active_ipv4(svc))
            .cloned()
            .collect();

        // Fallback to common physical interfaces if IPv4 detection found none
        if active_targets.is_empty() {
            for svc in &services {
                let lower = svc.to_ascii_lowercase();
                if lower.contains("wi-fi")
                    || lower.contains("wifi")
                    || lower.contains("ethernet")
                    || lower.contains("usb")
                {
                    active_targets.push(svc.clone());
                }
            }
        }

        let mut configured_any = false;
        for svc in active_targets {
            if macos_configure_service_proxy(&svc, port) {
                configured_any = true;
            }
        }

        if configured_any {
            return Ok(());
        }
    }

    let proxy = Sysproxy {
        enable: true,
        host: "127.0.0.1".into(),
        port,
        bypass: PROXY_BYPASS_DOMAINS.join(","),
    };

    proxy
        .set_system_proxy()
        .map_err(|e| format!("Failed to configure OS system proxy: {}", e))?;

    Ok(())
}

#[cfg(target_os = "macos")]
fn macos_proxy_output_matches(text: &str, port: u16) -> bool {
    let port_target = format!("Port: {}", port);
    let mut enabled = false;
    let mut host_ok = false;
    let mut port_ok = false;
    for line in text.lines() {
        let t = line.trim();
        if t.eq_ignore_ascii_case("Enabled: Yes") {
            enabled = true;
        } else if t == "Server: 127.0.0.1" || t == "Server: localhost" {
            host_ok = true;
        } else if t == port_target {
            port_ok = true;
        }
    }
    enabled && host_ok && port_ok
}

/// Checks whether the OS system proxy is currently configured and enabled for `127.0.0.1:<port>`.
pub fn is_system_proxy_active(port: u16) -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil")
            .arg("--proxy")
            .output()
        {
            let text = String::from_utf8_lossy(&output.stdout);
            let port_line = format!(": {}", port);
            let has_http = text.contains("HTTPEnable : 1")
                && text.contains("HTTPProxy : 127.0.0.1")
                && text.contains(&format!("HTTPPort {}", port_line));
            let has_https = text.contains("HTTPSEnable : 1")
                && text.contains("HTTPSProxy : 127.0.0.1")
                && text.contains(&format!("HTTPSPort {}", port_line));
            if has_http || has_https {
                return true;
            }
        }

        // Also inspect active IPv4 services directly (handles VPN / utun overrides where `scutil --proxy` omits NIC entries)
        for svc in list_macos_services() {
            if !macos_service_has_active_ipv4(&svc) {
                continue;
            }
            if let Ok(out) = std::process::Command::new("networksetup")
                .args(["-getwebproxy", &svc])
                .output()
            {
                if macos_proxy_output_matches(&String::from_utf8_lossy(&out.stdout), port) {
                    return true;
                }
            }
            if let Ok(out) = std::process::Command::new("networksetup")
                .args(["-getsecurewebproxy", &svc])
                .output()
            {
                if macos_proxy_output_matches(&String::from_utf8_lossy(&out.stdout), port) {
                    return true;
                }
            }
        }
        return false;
    }

    #[cfg(not(target_os = "macos"))]
    Sysproxy::get_system_proxy()
        .map(|p| p.enable && p.port == port && (p.host == "127.0.0.1" || p.host == "localhost"))
        .unwrap_or(false)
}

pub fn disable_system_proxy() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        for service in list_macos_services() {
            let _ = std::process::Command::new("networksetup")
                .args(["-setwebproxystate", &service, "off"])
                .output();
            let _ = std::process::Command::new("networksetup")
                .args(["-setsecurewebproxystate", &service, "off"])
                .output();
            let _ = std::process::Command::new("networksetup")
                .args(["-setsocksfirewallproxystate", &service, "off"])
                .output();
        }
    }

    let proxy = Sysproxy {
        enable: false,
        host: "127.0.0.1".into(),
        port: 1080,
        bypass: "".into(),
    };

    let _ = proxy.set_system_proxy();

    Ok(())
}
