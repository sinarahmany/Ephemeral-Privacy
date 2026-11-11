/// Known public WebRTC STUN/TURN relays used to discover true LAN/WAN IP addresses.
static STUN_TURN_DOMAINS: &[&str] = &[
    "stun.l.google.com",
    "stun1.l.google.com",
    "stun2.l.google.com",
    "stun3.l.google.com",
    "stun4.l.google.com",
    "stun.services.mozilla.com",
    "global.stun.twilio.com",
    "stun.stunprotocol.org",
    "turn.cloudflare.com",
    "stun.cloudflare.com",
    "relay.metered.ca",
    "openrelay.metered.ca",
    "numb.viagenie.ca",
    "stun.nextcloud.com",
    "stun.ekiga.net",
    "stun.ideasip.com",
    "stun.voipbuster.com",
    "stun.voxgratia.org",
    "stun.sipgate.net",
    "stun.freeswitch.org",
    "global.turn.twilio.com",
    "turn.twilio.com",
    "relay.twilio.com",
    "xirsys.com",
    "turn.xirsys.com",
];

/// Standard STUN / TURN / ICE discovery ports
static STUN_TURN_PORTS: &[u16] = &[
    3478,  // STUN/TURN UDP & TCP
    5349,  // STUNS / TURN-TLS
    19302, // Google WebRTC STUN
    19303,
    19304,
    19305,
    19306,
    19307,
    19308,
    19309,
];

/// Returns true if the domain or port corresponds to a WebRTC STUN/TURN IP-discovery endpoint.
pub fn is_webrtc_stun_target(host: &str, port: Option<u16>) -> Option<&'static str> {
    if let Some(p) = port {
        if STUN_TURN_PORTS.contains(&p) {
            return Some("WebRTC STUN/TURN Port");
        }
    }

    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return None;
    }

    if STUN_TURN_DOMAINS
        .iter()
        .any(|&d| clean == d || clean.ends_with(&format!(".{}", d)))
    {
        return Some("Known WebRTC STUN/TURN Server");
    }

    if clean.starts_with("stun.")
        || clean.starts_with("turn.")
        || clean.starts_with("stun0")
        || clean.starts_with("turn0")
        || clean.contains(".stun.")
        || clean.contains(".turn.")
        || clean.contains("turnserver")
        || clean.contains("stunserver")
        || clean.starts_with("stun-")
        || clean.starts_with("turn-")
    {
        return Some("WebRTC STUN/TURN Endpoint Pattern");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webrtc_stun_detection() {
        assert!(is_webrtc_stun_target("stun.l.google.com", Some(19302)).is_some());
        assert!(is_webrtc_stun_target("stun.example.org", Some(443)).is_some());
        assert!(is_webrtc_stun_target("1.2.3.4", Some(3478)).is_some());
        assert!(is_webrtc_stun_target("turn.cloudflare.com", Some(5349)).is_some());
        assert!(is_webrtc_stun_target("news.ycombinator.com", Some(443)).is_none());
        assert!(is_webrtc_stun_target("github.com", None).is_none());
    }
}
