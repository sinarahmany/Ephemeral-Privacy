use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsTelemetryItem {
    pub id: &'static str,
    pub name: &'static str,
    pub os: &'static str,
    pub description: &'static str,
    pub risk_level: &'static str,
}

pub static TELEMETRY_PROFILES: &[OsTelemetryItem] = &[
    OsTelemetryItem {
        id: "mac_diagnostics",
        name: "Apple Diagnostics & Crash Submissions",
        os: "macos",
        description: "Disables automatic diagnostic log uploads and analytics reporting to Apple servers.",
        risk_level: "Recommended",
    },
    OsTelemetryItem {
        id: "mac_spotlight_web",
        name: "Spotlight Suggestions & Siri Queries",
        os: "macos",
        description: "Prevents local Finder/Spotlight searches from sending keystroke queries to Apple.",
        risk_level: "High Privacy",
    },
    OsTelemetryItem {
        id: "win_diagtrack",
        name: "Windows Connected User Experiences & Telemetry",
        os: "windows",
        description: "Silences the DiagTrack service and prevents periodic diagnostic payloads to Microsoft.",
        risk_level: "Recommended",
    },
    OsTelemetryItem {
        id: "win_ad_id",
        name: "Windows Advertising ID & Activity Tracking",
        os: "windows",
        description: "Revokes unique machine advertising identifier used by Windows Store apps.",
        risk_level: "Recommended",
    },
    OsTelemetryItem {
        id: "linux_whoopsie",
        name: "Ubuntu Whoopsie & Apport Crash Metrics",
        os: "linux",
        description: "Disables Canonical daemon that reports system crash metrics and package metadata.",
        risk_level: "Recommended",
    },
];

pub fn get_telemetry_profiles() -> Vec<OsTelemetryItem> {
    TELEMETRY_PROFILES.to_vec()
}
