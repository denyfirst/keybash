//! The browser's MCS Connect Initial, decoded, checked and re-encoded: it is
//! never forwarded as it came.

use std::borrow::Cow;

use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::gcc::{ClientGccBlocks, ConferenceCreateRequest};
use ironrdp_pdu::x224::{X224, X224Data};
use ironrdp_pdu::{mcs, nego};

/// A Connect Initial larger than this is refused before decoding.
pub const MAX_CONNECT_INITIAL: usize = 16 * 1024;

/// Windows' scales Keybash opens desktops at: `identity.desktopDPIs` as percent.
const SCALES: [u32; 5] = [100, 125, 150, 175, 200];

#[derive(Debug, PartialEq, Eq)]
pub struct Refusal(pub &'static str);

/// `identity.DesktopSize` at a scale: even, at least 200 by 200, at most full
/// HD times the scale. Both checks must agree; the gateway's tests hold the
/// same table.
pub fn desktop_allowed(width: u16, height: u16, scale: u32) -> bool {
    if !SCALES.contains(&scale) {
        return false;
    }
    let (w, h) = (u32::from(width), u32::from(height));
    w >= 200 && h >= 200 && w <= 1920 * scale / 100 && h <= 1080 * scale / 100 && w % 2 == 0 && h % 2 == 0
}

/// The static channels a browser desktop may join, by name, in lower case.
fn channel_allowed(name: &str, clipboard: bool) -> bool {
    name == "drdynvc" || (clipboard && name == "cliprdr")
}

/// Checks the browser's Connect Initial and returns the one sent to Windows.
///
/// - The browser was told TLS was selected; Windows must hear what it selected.
/// - The desktop must be within the bounds at its scale.
/// - Only allowed static channels, each once. The page asks for nothing else,
///   so any other is refused rather than dropped: dropping one would shift the
///   channel numbers Windows answers with.
/// - No monitor layout (one monitor, the desktop size), no redirection, no
///   UDP transport: those blocks are removed.
pub fn connect_initial(tpkt: &[u8], selected: nego::SecurityProtocol, clipboard: bool) -> Result<Vec<u8>, Refusal> {
    if tpkt.len() > MAX_CONNECT_INITIAL {
        return Err(Refusal("Connect Initial too large"));
    }
    let X224(carrier) = decode::<X224<X224Data<'_>>>(tpkt).map_err(|_| Refusal("not an X.224 data PDU"))?;
    let mut initial =
        decode::<mcs::ConnectInitial>(&carrier.data).map_err(|_| Refusal("not an MCS Connect Initial"))?;
    let mut blocks: ClientGccBlocks = initial.conference_create_request.gcc_blocks().clone();

    let core = &mut blocks.core;
    if core.optional_data.server_selected_protocol != Some(nego::SecurityProtocol::SSL) {
        return Err(Refusal("the browser must have been told TLS"));
    }
    core.optional_data.server_selected_protocol = Some(selected);
    let scale = core.optional_data.desktop_scale_factor.unwrap_or(100);
    if !desktop_allowed(core.desktop_width, core.desktop_height, scale) {
        return Err(Refusal("desktop size outside the bounds"));
    }
    if !matches!(core.optional_data.device_scale_factor, None | Some(100 | 140 | 180)) {
        return Err(Refusal("device scale factor"));
    }
    if blocks.monitor.is_some() || blocks.monitor_extended.is_some() {
        return Err(Refusal("monitor layout"));
    }
    blocks.cluster = None;
    blocks.multi_transport_channel = None;
    blocks.message_channel = None;

    let mut seen: Vec<String> = Vec::new();
    for channel in blocks.network.iter().flat_map(|n| n.channels.iter()) {
        let name = channel
            .name
            .as_str()
            .map(str::to_ascii_lowercase)
            .ok_or(Refusal("channel name"))?;
        if !channel_allowed(&name, clipboard) || seen.contains(&name) {
            return Err(Refusal("static channel not allowed"));
        }
        seen.push(name);
    }

    initial.conference_create_request = ConferenceCreateRequest::new(blocks).map_err(|_| Refusal("encode"))?;
    let body = encode_vec(&initial).map_err(|_| Refusal("encode"))?;
    encode_vec(&X224(X224Data { data: Cow::Owned(body) })).map_err(|_| Refusal("encode"))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ironrdp_connector::{ClientConnector, Credentials, DesktopSize, Sequence as _};
    use ironrdp_core::WriteBuf;
    use ironrdp_pdu::gcc::{ChannelDef, ChannelName, ChannelOptions, ClientMonitorData, ClientNetworkData};
    use ironrdp_pdu::rdp::client_info::{PerformanceFlags, TimezoneInfo};

    /// What IronRDP's browser client is configured with: TLS only, the proxy
    /// does NLA.
    pub(crate) fn browser_config(width: u16, height: u16, scale: u32) -> ironrdp_connector::Config {
        ironrdp_connector::Config {
            credentials: Credentials::UsernamePassword {
                username: String::new(),
                password: String::new(),
            },
            domain: None,
            enable_tls: true,
            enable_credssp: false,
            enable_standard_rdp_security: false,
            keyboard_type: ironrdp_pdu::gcc::KeyboardType::IBM_ENHANCED,
            keyboard_subtype: 0,
            keyboard_layout: 0,
            keyboard_functional_keys_count: 12,
            connection_type: ironrdp_pdu::gcc::ConnectionType::Lan,
            ime_file_name: String::new(),
            dig_product_id: String::new(),
            desktop_size: DesktopSize { width, height },
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
            support_dyn_vc_gfx_protocol: true,
            rdp_version: ironrdp_pdu::gcc::RdpVersion::V5_PLUS,
            performance_flags: PerformanceFlags::default(),
            desktop_scale_factor: scale,
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

    /// The Connect Initial IronRDP's connector sends after TLS was confirmed.
    pub(crate) fn browser_connect_initial(width: u16, height: u16, scale: u32) -> Vec<u8> {
        let mut connector = ClientConnector::new(
            browser_config(width, height, scale),
            "127.0.0.1:0".parse().expect("addr"),
        );
        let mut buf = WriteBuf::new();
        connector.step_no_input(&mut buf).expect("X.224 request");
        let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
            flags: nego::ResponseFlags::empty(),
            protocol: nego::SecurityProtocol::SSL,
        }))
        .expect("confirm");
        buf.clear();
        connector.step(&confirm, None, &mut buf).expect("confirm accepted");
        connector.mark_security_upgrade_as_done();
        buf.clear();
        connector.step_no_input(&mut buf).expect("Connect Initial");
        buf.filled().to_vec()
    }

    fn blocks_of(tpkt: &[u8]) -> ClientGccBlocks {
        let X224(carrier) = decode::<X224<X224Data<'_>>>(tpkt).expect("x224");
        decode::<mcs::ConnectInitial>(&carrier.data)
            .expect("mcs")
            .conference_create_request
            .gcc_blocks()
            .clone()
    }

    fn with_blocks(tpkt: &[u8], change: impl FnOnce(&mut ClientGccBlocks)) -> Vec<u8> {
        let X224(carrier) = decode::<X224<X224Data<'_>>>(tpkt).expect("x224");
        let mut initial = decode::<mcs::ConnectInitial>(&carrier.data).expect("mcs");
        let mut blocks = initial.conference_create_request.gcc_blocks().clone();
        change(&mut blocks);
        initial.conference_create_request = ConferenceCreateRequest::new(blocks).expect("blocks");
        let body = encode_vec(&initial).expect("mcs");
        encode_vec(&X224(X224Data { data: Cow::Owned(body) })).expect("x224")
    }

    fn channels(names: &[&str]) -> ClientNetworkData {
        ClientNetworkData {
            channels: names
                .iter()
                .map(|n| ChannelDef {
                    name: ChannelName::from_utf8(n).expect("name"),
                    options: ChannelOptions::INITIALIZED,
                })
                .collect(),
        }
    }

    #[test]
    fn the_desktop_bounds_match_the_gateway() {
        // The same table as identity.DesktopSize.
        for (w, h, scale, ok) in [
            (1920, 1080, 100, true),
            (1922, 1080, 100, false),
            (1920, 1082, 100, false),
            (200, 200, 100, true),
            (198, 200, 100, false),
            (1601, 900, 100, false),
            (1600, 901, 100, false),
            (2400, 1350, 125, true),
            (2402, 1350, 125, false),
            (2880, 1620, 150, true),
            (3360, 1890, 175, true),
            (3840, 2160, 200, true),
            (3842, 2160, 200, false),
            (1920, 1080, 110, false),
            (1920, 1080, 0, false),
            (1920, 1080, 300, false),
        ] {
            assert_eq!(desktop_allowed(w, h, scale), ok, "{w}x{h} at {scale}%");
        }
    }

    #[test]
    fn windows_hears_its_protocol_and_the_rest_is_unchanged() {
        let sent = browser_connect_initial(1600, 900, 100);
        let out = connect_initial(&sent, nego::SecurityProtocol::HYBRID_EX, false).expect("allowed");
        let (before, after) = (blocks_of(&sent), blocks_of(&out));
        assert_eq!(
            after.core.optional_data.server_selected_protocol,
            Some(nego::SecurityProtocol::HYBRID_EX)
        );
        let mut expected = before.clone();
        expected.core.optional_data.server_selected_protocol = Some(nego::SecurityProtocol::HYBRID_EX);
        expected.cluster = None;
        expected.multi_transport_channel = None;
        expected.message_channel = None;
        assert_eq!(after, expected);
        // A scaled desktop within its bounds passes too.
        connect_initial(
            &browser_connect_initial(3840, 2160, 200),
            nego::SecurityProtocol::HYBRID,
            false,
        )
        .expect("200%");
    }

    #[test]
    fn allowed_channels_pass_and_any_other_ends_it() {
        let base = browser_connect_initial(1600, 900, 100);
        let with = |names: &[&str]| with_blocks(&base, |b| b.network = Some(channels(names)));
        connect_initial(&with(&["drdynvc"]), nego::SecurityProtocol::HYBRID, false).expect("drdynvc");
        connect_initial(&with(&["DRDYNVC", "cliprdr"]), nego::SecurityProtocol::HYBRID, true)
            .expect("with the clipboard");
        connect_initial(&with(&[]), nego::SecurityProtocol::HYBRID, false).expect("none");
        for (names, clipboard) in [
            (&["cliprdr"][..], false),
            (&["drdynvc", "rdpdr"][..], true),
            (&["rdpsnd"][..], true),
            (&["rail"][..], true),
            (&["drdynvc", "drdynvc"][..], false),
            (&["drdynvc", "Drdynvc"][..], false),
        ] {
            assert_eq!(
                connect_initial(&with(names), nego::SecurityProtocol::HYBRID, clipboard),
                Err(Refusal("static channel not allowed")),
                "{names:?} clipboard {clipboard}"
            );
        }
    }

    #[test]
    fn sizes_monitors_and_protocols_outside_the_rules_are_refused() {
        let base = browser_connect_initial(1600, 900, 100);
        let refused = |packet: Vec<u8>| connect_initial(&packet, nego::SecurityProtocol::HYBRID, true).is_err();
        assert!(refused(browser_connect_initial(1922, 1080, 100)));
        assert!(refused(browser_connect_initial(3840, 2160, 100)));
        assert!(refused(browser_connect_initial(1600, 900, 300)));
        assert!(refused(with_blocks(&base, |b| b
            .core
            .optional_data
            .server_selected_protocol =
            Some(nego::SecurityProtocol::HYBRID))));
        // Absent: the optional fields after it must be absent too to encode.
        assert!(refused(with_blocks(&base, |b| {
            let o = &mut b.core.optional_data;
            o.server_selected_protocol = None;
            o.desktop_physical_width = None;
            o.desktop_physical_height = None;
            o.desktop_orientation = None;
            o.desktop_scale_factor = None;
            o.device_scale_factor = None;
        })));
        assert!(refused(with_blocks(&base, |b| b
            .core
            .optional_data
            .device_scale_factor = Some(150))));
        assert!(refused(
            with_blocks(&base, |b| b.monitor = Some(ClientMonitorData { monitors: Vec::new() }))
        ));
    }

    #[test]
    fn malformed_input_is_refused_not_trusted() {
        let base = browser_connect_initial(1600, 900, 100);
        assert!(connect_initial(&[], nego::SecurityProtocol::HYBRID, false).is_err());
        assert!(connect_initial(&base[..base.len() / 2], nego::SecurityProtocol::HYBRID, false).is_err());
        assert!(
            connect_initial(
                &vec![3u8; MAX_CONNECT_INITIAL + 1],
                nego::SecurityProtocol::HYBRID,
                false
            )
            .is_err()
        );
        // Every single-byte change either refuses or still meets every rule.
        for i in 0..base.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                let mut bad = base.clone();
                bad[i] ^= flip;
                if let Ok(out) = connect_initial(&bad, nego::SecurityProtocol::HYBRID, false) {
                    let b = blocks_of(&out);
                    assert_eq!(
                        b.core.optional_data.server_selected_protocol,
                        Some(nego::SecurityProtocol::HYBRID)
                    );
                    let scale = b.core.optional_data.desktop_scale_factor.unwrap_or(100);
                    assert!(desktop_allowed(b.core.desktop_width, b.core.desktop_height, scale));
                    assert!(b.monitor.is_none() && b.cluster.is_none() && b.multi_transport_channel.is_none());
                    assert!(
                        b.network.iter().flat_map(|n| n.channels.iter()).all(|c| c
                            .name
                            .as_str()
                            .map(str::to_ascii_lowercase)
                            .as_deref()
                            == Some("drdynvc"))
                    );
                }
            }
        }
    }
}
