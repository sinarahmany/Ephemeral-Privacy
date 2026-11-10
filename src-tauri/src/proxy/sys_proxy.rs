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

    proxy
        .set_system_proxy()
        .map_err(|e| format!("Failed to reset OS system proxy: {}", e))?;

    Ok(())
}
