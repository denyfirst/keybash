//! The connector configuration the proxy uses toward Windows. The proxy's
//! connector only runs X.224 and CredSSP; the browser's own connector sends
//! everything after that, checked by `policy`.

use ironrdp_connector::{Config, Credentials, DesktopSize};
use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

pub fn connector_config() -> Config {
    Config {
        credentials: Credentials::UsernamePassword {
            username: String::new(),
            password: String::new(),
        },
        domain: None,
        enable_tls: true,
        enable_credssp: true,
        enable_standard_rdp_security: false,
        keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: DesktopSize {
            width: 1024,
            height: 768,
        },
        monitor_layout: None,
        bitmap: None,
        client_build: 0,
        client_name: "keybash".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),
        platform: ironrdp_pdu::rdp::capability_sets::MajorPlatformType::UNSPECIFIED,
        compression_type: None,
        enable_server_pointer: true,
        autologon: false,
        enable_audio_playback: false,
        enable_audio_capture: false,
        request_data: None,
        pointer_software_rendering: false,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
        rdp_version: ironrdp_pdu::gcc::RdpVersion::V5_PLUS,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        desktop_physical_size: None,
        desktop_orientation: None,
        device_scale_factor: None,
        monitor_extended_layout: None,
        relative_mouse_input: false,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
        remote_application_mode: false,
        rail_support_level: ironrdp_pdu::rdp::capability_sets::RailSupportLevel::SUPPORTED,
    }
}
