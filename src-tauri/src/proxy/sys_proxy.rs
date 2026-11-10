use sysproxy::Sysproxy;

pub fn enable_system_proxy(port: u16) -> Result<(), String> {
    let proxy = Sysproxy {
        enable: true,
        host: "127.0.0.1".into(),
        port,
        bypass: "localhost,127.0.0.1,::1,192.168.0.0/16,10.0.0.0/8".into(),
    };

    proxy
        .set_system_proxy()
        .map_err(|e| format!("Failed to configure OS system proxy: {}", e))?;

    Ok(())
}

pub fn disable_system_proxy() -> Result<(), String> {
    let proxy = Sysproxy {
        enable: false,
        host: "127.0.0.1".into(),
        port: 1080,
        bypass: "".into(),
    };

    let _ = proxy.set_system_proxy();

    // Thorough fallback: Ensure ALL network interfaces on macOS are restored to direct connection
    #[cfg(target_os = "macos")]
    {
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
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setwebproxystate", service, "off"])
                        .output();
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setsecurewebproxystate", service, "off"])
                        .output();
                    let _ = std::process::Command::new("networksetup")
                        .args(["-setsocksfirewallproxystate", service, "off"])
                        .output();
                }
            }
        }
    }

    Ok(())
}

