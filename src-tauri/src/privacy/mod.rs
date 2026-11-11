pub mod audit;
pub mod clipboard;
pub mod hardware_sentinel;
pub mod os_telemetry;
pub mod pii_redactor;

pub use audit::{run_full_privacy_audit, AuditCheckResult, PrivacyAuditReport};
pub use clipboard::start_clipboard_monitor;
pub use hardware_sentinel::{probe_hardware_state, start_hardware_sentinel, HardwareStatus};
pub use os_telemetry::{get_telemetry_profiles, OsTelemetryItem};
pub use pii_redactor::{redact_pii, restore_pii, RedactionResult};
