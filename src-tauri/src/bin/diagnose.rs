use sysproxy::Sysproxy;

#[tokio::main]
async fn main() {
    println!("=== 1. DIAGNOSING SYSPROXY ON MACOS ===");
    match Sysproxy::get_system_proxy() {
        Ok(curr) => println!("Current system proxy: host={}, port={}, enabled={}", curr.host, curr.port, curr.enable),
        Err(e) => println!("Error getting system proxy: {}", e),
    }

    let test_proxy = Sysproxy {
        enable: true,
        host: "127.0.0.1".into(),
        port: 1080,
        bypass: "localhost,127.0.0.1".into(),
    };
    match test_proxy.set_system_proxy() {
        Ok(_) => println!("Successfully set system proxy via sysproxy!"),
        Err(e) => println!("FAILED to set system proxy: {}", e),
    }

    match Sysproxy::get_system_proxy() {
        Ok(curr) => println!("After set: host={}, port={}, enabled={}", curr.host, curr.port, curr.enable),
        Err(e) => println!("Error reading back: {}", e),
    }

    // Reset back
    let reset_proxy = Sysproxy {
        enable: false,
        host: "127.0.0.1".into(),
        port: 1080,
        bypass: "".into(),
    };
    let _ = reset_proxy.set_system_proxy();
    println!("Restored proxy to disabled.");

    println!("\n=== 2. DIAGNOSING ARBOARD CLIPBOARD ===");
    match arboard::Clipboard::new() {
        Ok(mut cb) => {
            match cb.get_text() {
                Ok(t) => println!("Read clipboard successfully (len={})", t.len()),
                Err(e) => println!("Clipboard get_text error: {}", e),
            }
        }
        Err(e) => println!("Failed to initialize arboard Clipboard: {}", e),
    }
}
