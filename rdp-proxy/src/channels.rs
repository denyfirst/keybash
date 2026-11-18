//! What crosses the proxy after the handshake (docs/BROWSER-RDP-PROXY.md,
//! 2c): every PDU framed and bounded, the static channels Windows numbered,
//! on `drdynvc` only the dynamic channels Keybash allows, opened by the
//! browser itself, and on `cliprdr` only text (crate::clipboard). Anything
//! else ends the session as "refused".

use std::collections::HashMap;
use std::time::Instant;

use ironrdp_core::decode;
use ironrdp_pdu::x224::{X224, X224Data};
use ironrdp_pdu::{Action, find_size, mcs};

use crate::clipboard::Clipboard;
use crate::policy::{Refusal, desktop_allowed};

/// What goes on in place of a PDU that passed its checks.
#[derive(Debug, PartialEq, Eq)]
pub enum Pass {
    Unchanged,
    /// These PDUs instead, possibly none: a clipboard message is gathered
    /// whole and written again.
    Instead(Vec<Vec<u8>>),
}

/// The largest PDU passed: a TPKT's own limit; fast-path is smaller still.
pub const MAX_PDU: usize = 65_535;

/// The dynamic channels a browser desktop may open.
const GRAPHICS: &str = "Microsoft::Windows::RDS::Graphics";
const DISPLAY: &str = "Microsoft::Windows::RDS::DisplayControl";

/// The largest whole message on `drdynvc`, chunks together.
const MAX_SVC_MESSAGE: u32 = 16 * 1024 * 1024;

// Static virtual channel chunk flags (MS-RDPBCGR 2.2.6.1.1).
const CHANNEL_FLAG_FIRST: u32 = 0x01;
const CHANNEL_FLAG_LAST: u32 = 0x02;
const CHANNEL_PACKET_COMPRESSED: u32 = 0x0020_0000;

/// Splits one direction's bytes into whole RDP PDUs, TPKT or fast-path.
#[derive(Default)]
pub struct Splitter {
    buf: Vec<u8>,
}

impl Splitter {
    /// Adds bytes and returns every PDU now complete, in order. What remains
    /// is at most one PDU's beginning.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<(Action, Vec<u8>)>, Refusal> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            let Some(info) = find_size(&self.buf).map_err(|_| Refusal("PDU framing"))? else {
                break;
            };
            // No PDU is shorter than its own header: 7 bytes of TPKT and X.224, 2 of fast-path.
            // IronRDP's find_size refuses these lengths too at the pinned commit; the rule is
            // kept here so it holds if that changes.
            let least = if info.action == Action::X224 { 7 } else { 2 };
            if info.length < least || info.length > MAX_PDU {
                return Err(Refusal("PDU size"));
            }
            if self.buf.len() < info.length {
                break;
            }
            out.push((info.action, self.buf.drain(..info.length).collect()));
        }
        if self.buf.len() > MAX_PDU {
            return Err(Refusal("PDU size"));
        }
        Ok(out)
    }
}

enum Dvc {
    /// Windows asked to open it; the browser has not answered yet.
    Requested {
        allowed: bool,
        display: bool,
    },
    Open {
        display: bool,
    },
}

/// Whether a chunked `drdynvc` message is under way in one direction.
#[derive(Default)]
struct Chunks {
    open: bool,
}

pub struct Channels {
    clipboard: bool,
    /// The static channels the browser asked for, in order, lower case.
    names: Vec<String>,
    io: Option<u16>,
    user: Option<u16>,
    drdynvc: Option<u16>,
    cliprdr: Option<u16>,
    clip: Clipboard,
    dvc: HashMap<u32, Dvc>,
    from_server: Chunks,
    from_browser: Chunks,
    /// The account the proxy signed in with: user name and domain.
    account: Option<(String, Option<String>)>,
    /// Whether the browser's Client Info has passed, written again.
    client_info: bool,
}

impl Channels {
    pub fn new(names: Vec<String>, clipboard: bool) -> Self {
        Self {
            clipboard,
            names,
            io: None,
            user: None,
            drdynvc: None,
            cliprdr: None,
            clip: Clipboard::default(),
            dvc: HashMap::new(),
            from_server: Chunks::default(),
            from_browser: Chunks::default(),
            account: None,
            client_info: false,
        }
    }

    /// The account the browser's Client Info will name. Without one, the
    /// Client Info is refused.
    pub fn for_account(mut self, user: &str, domain: &str) -> Self {
        let domain = (!domain.is_empty()).then(|| domain.to_owned());
        self.account = Some((user.to_owned(), domain));
        self
    }

    /// Checks one PDU from Windows before it goes to the browser.
    pub fn server_pdu(&mut self, action: Action, pdu: &[u8]) -> Result<Pass, Refusal> {
        if action == Action::FastPath {
            return Ok(Pass::Unchanged); // output updates; they carry no channel data
        }
        if self.io.is_none() {
            return self.connect_response(pdu).map(|()| Pass::Unchanged);
        }
        match decode::<X224<mcs::McsMessage<'_>>>(pdu)
            .map_err(|_| Refusal("MCS from Windows"))?
            .0
        {
            mcs::McsMessage::AttachUserConfirm(confirm) => {
                self.user = Some(confirm.initiator_id);
                Ok(Pass::Unchanged)
            }
            mcs::McsMessage::ChannelJoinConfirm(_) | mcs::McsMessage::DisconnectProviderUltimatum(_) => {
                Ok(Pass::Unchanged)
            }
            mcs::McsMessage::SendDataIndication(data) => {
                if Some(data.channel_id) == self.io || Some(data.channel_id) == self.user {
                    Ok(Pass::Unchanged)
                } else if Some(data.channel_id) == self.drdynvc {
                    self.svc(true, &data.user_data).map(|()| Pass::Unchanged)
                } else if Some(data.channel_id) == self.cliprdr {
                    let now = Instant::now();
                    let pdus = self
                        .clip
                        .chunk(true, data.initiator_id, data.channel_id, &data.user_data, now)?;
                    Ok(Pass::Instead(pdus))
                } else {
                    Err(Refusal("data on a channel not allowed"))
                }
            }
            _ => Err(Refusal("MCS from Windows")),
        }
    }

    /// Checks one PDU from the browser before it goes to Windows.
    pub fn browser_pdu(&mut self, action: Action, pdu: &[u8]) -> Result<Pass, Refusal> {
        if action == Action::FastPath {
            return Ok(Pass::Unchanged); // input events
        }
        match decode::<X224<mcs::McsMessage<'_>>>(pdu)
            .map_err(|_| Refusal("MCS from the browser"))?
            .0
        {
            mcs::McsMessage::ErectDomainRequest(_)
            | mcs::McsMessage::AttachUserRequest(_)
            | mcs::McsMessage::DisconnectProviderUltimatum(_) => Ok(Pass::Unchanged),
            mcs::McsMessage::ChannelJoinRequest(join) => {
                let known = [self.io, self.user, self.drdynvc, self.cliprdr];
                if known.contains(&Some(join.channel_id)) {
                    Ok(Pass::Unchanged)
                } else {
                    Err(Refusal("joining a channel not allowed"))
                }
            }
            mcs::McsMessage::SendDataRequest(data) => {
                if Some(data.channel_id) == self.io && !self.client_info {
                    self.client_info(data.initiator_id, data.channel_id, &data.user_data)
                } else if Some(data.channel_id) == self.io || Some(data.channel_id) == self.user {
                    Ok(Pass::Unchanged)
                } else if Some(data.channel_id) == self.drdynvc {
                    self.svc(false, &data.user_data).map(|()| Pass::Unchanged)
                } else if Some(data.channel_id) == self.cliprdr {
                    let now = Instant::now();
                    let pdus = self
                        .clip
                        .chunk(false, data.initiator_id, data.channel_id, &data.user_data, now)?;
                    Ok(Pass::Instead(pdus))
                } else {
                    Err(Refusal("data on a channel not allowed"))
                }
            }
            _ => Err(Refusal("MCS from the browser")),
        }
    }

    /// The browser's Client Info (MS-RDPBCGR 2.2.1.11), its first message on
    /// the I/O channel, written again:
    /// - it names the account the proxy signed in with, with no password and
    ///   no redirection cookie in the password's place;
    /// - it carries no auto-reconnect cookie, so it cannot reach a session
    ///   the proxy did not sign in for;
    /// - a program instead of the desktop, a working folder or RemoteApp
    ///   ends the session, as today's guacd path never asks for them.
    fn client_info(&mut self, initiator: u16, channel: u16, data: &[u8]) -> Result<Pass, Refusal> {
        use ironrdp_pdu::rdp::ClientInfoPdu;
        use ironrdp_pdu::rdp::client_info::{ClientInfoFlags, Credentials};
        use ironrdp_pdu::rdp::headers::BasicSecurityHeaderFlags;

        let (user, domain) = self.account.clone().ok_or(Refusal("no account for the Client Info"))?;
        let mut pdu = decode::<ClientInfoPdu>(data).map_err(|_| Refusal("Client Info"))?;
        let info = &mut pdu.client_info;
        if pdu.security_header.flags != BasicSecurityHeaderFlags::INFO_PKT
            || !info.alternate_shell.is_empty()
            || !info.work_dir.is_empty()
            || info.flags.contains(ClientInfoFlags::RAIL)
        {
            return Err(Refusal("Client Info asks for more than the desktop"));
        }
        info.credentials = Credentials {
            username: user,
            password: String::new(),
            domain,
        };
        info.password_cookie = None;
        info.extra_info.optional_data = without_reconnect_cookie(&info.extra_info.optional_data);
        let written = ironrdp_core::encode_vec(&pdu).map_err(|_| Refusal("Client Info"))?;
        let out = ironrdp_core::encode_vec(&X224(mcs::McsMessage::SendDataRequest(mcs::SendDataRequest {
            initiator_id: initiator,
            channel_id: channel,
            user_data: std::borrow::Cow::Owned(written),
        })))
        .map_err(|_| Refusal("Client Info"))?;
        self.client_info = true;
        Ok(Pass::Instead(vec![out]))
    }

    /// Windows' MCS Connect Response numbers the channels the browser asked
    /// for, in the same order.
    fn connect_response(&mut self, pdu: &[u8]) -> Result<(), Refusal> {
        let X224(carrier) = decode::<X224<X224Data<'_>>>(pdu).map_err(|_| Refusal("not an X.224 data PDU"))?;
        let response =
            decode::<mcs::ConnectResponse>(&carrier.data).map_err(|_| Refusal("not an MCS Connect Response"))?;
        let network = &response.conference_create_response.gcc_blocks().network;
        if network.channel_ids.len() != self.names.len() {
            return Err(Refusal("channel numbering"));
        }
        for (name, &id) in self.names.iter().zip(&network.channel_ids) {
            match name.as_str() {
                "drdynvc" => self.drdynvc = Some(id),
                "cliprdr" if self.clipboard => self.cliprdr = Some(id),
                _ => return Err(Refusal("static channel not allowed")),
            }
        }
        self.io = Some(network.io_channel);
        Ok(())
    }

    /// One chunk of a `drdynvc` message. Its dynamic channel PDU starts in the
    /// first chunk, so that is where it is checked; the rest follow it.
    fn svc(&mut self, from_server: bool, data: &[u8]) -> Result<(), Refusal> {
        let header = data.get(..8).ok_or(Refusal("channel chunk"))?;
        let total = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
        let flags = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
        if flags & CHANNEL_PACKET_COMPRESSED != 0 || total > MAX_SVC_MESSAGE {
            return Err(Refusal("channel chunk"));
        }
        let first = flags & CHANNEL_FLAG_FIRST != 0;
        let last = flags & CHANNEL_FLAG_LAST != 0;
        let chunks = if from_server {
            &mut self.from_server
        } else {
            &mut self.from_browser
        };
        if first == chunks.open {
            // A first chunk inside a message, or a later one outside it.
            return Err(Refusal("channel chunk order"));
        }
        chunks.open = !last;
        if first {
            self.dynamic(from_server, &data[8..])?;
        }
        Ok(())
    }

    /// The dynamic channel PDU at the start of a `drdynvc` message
    /// (MS-RDPEDYC 2.2).
    fn dynamic(&mut self, from_server: bool, pdu: &[u8]) -> Result<(), Refusal> {
        let (&header, rest) = pdu.split_first().ok_or(Refusal("dynamic channel PDU"))?;
        let cmd = header >> 4;
        let id_size = match header & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return Err(Refusal("dynamic channel PDU")),
        };
        if cmd == 0x05 {
            return Ok(()); // capabilities, both ways
        }
        let id_bytes = rest.get(..id_size).ok_or(Refusal("dynamic channel PDU"))?;
        let id = id_bytes.iter().rev().fold(0u32, |n, &b| n << 8 | u32::from(b));
        let body = &rest[id_size..];
        match (cmd, from_server) {
            // Create: Windows names the channel; the browser answers.
            (0x01, true) => {
                let end = body.iter().position(|&b| b == 0).ok_or(Refusal("channel name"))?;
                let name = std::str::from_utf8(&body[..end]).map_err(|_| Refusal("channel name"))?;
                let allowed = name == GRAPHICS || name == DISPLAY;
                if self.dvc.contains_key(&id) {
                    return Err(Refusal("dynamic channel reused"));
                }
                self.dvc.insert(
                    id,
                    Dvc::Requested {
                        allowed,
                        display: name == DISPLAY,
                    },
                );
                Ok(())
            }
            (0x01, false) => {
                let status = body.get(..4).ok_or(Refusal("create response"))?;
                let failed = i32::from_le_bytes([status[0], status[1], status[2], status[3]]) < 0;
                match self.dvc.remove(&id) {
                    Some(Dvc::Requested { .. }) if failed => Ok(()),
                    Some(Dvc::Requested { allowed: true, display }) => {
                        self.dvc.insert(id, Dvc::Open { display });
                        Ok(())
                    }
                    _ => Err(Refusal("opening a dynamic channel not allowed")),
                }
            }
            // Data: only on a channel the browser opened.
            (0x02 | 0x03 | 0x06 | 0x07, _) => match self.dvc.get(&id) {
                Some(Dvc::Open { display: true }) if !from_server => {
                    if cmd != 0x03 {
                        return Err(Refusal("display layout fragmented or compressed"));
                    }
                    display_layout(body)
                }
                Some(Dvc::Open { .. }) => Ok(()),
                _ => Err(Refusal("data on a dynamic channel not open")),
            },
            // Close, either way.
            (0x04, _) => {
                self.dvc.remove(&id);
                Ok(())
            }
            _ => Err(Refusal("dynamic channel command")),
        }
    }
}

/// The Client Info's optional fields, in their fixed order, up to and without
/// the auto-reconnect cookie.
fn without_reconnect_cookie(
    old: &ironrdp_pdu::rdp::client_info::ExtendedClientOptionalInfo,
) -> ironrdp_pdu::rdp::client_info::ExtendedClientOptionalInfo {
    let start = ironrdp_pdu::rdp::client_info::ExtendedClientOptionalInfo::builder();
    let Some(timezone) = old.timezone() else {
        return start.build();
    };
    let next = start.timezone(timezone.clone());
    let Some(id) = old.session_id() else {
        return next.build();
    };
    let next = next.session_id(id);
    let Some(flags) = old.performance_flags() else {
        return next.build();
    };
    next.performance_flags(flags).build()
}

/// A display-control monitor layout from the browser (MS-RDPEDISP 2.2.2.2):
/// one primary monitor at the origin, within the desktop bounds.
fn display_layout(pdu: &[u8]) -> Result<(), Refusal> {
    let word = |at: usize| -> Result<u32, Refusal> {
        let b = pdu.get(at..at + 4).ok_or(Refusal("display layout"))?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    // Header: type and length; then the entry size and the count.
    if word(0)? != 2 || usize::try_from(word(4)?).ok() != Some(pdu.len()) || word(8)? != 40 || word(12)? != 1 {
        return Err(Refusal("display layout"));
    }
    if pdu.len() != 16 + 40 {
        return Err(Refusal("display layout"));
    }
    let (flags, left, top, width, height) = (word(16)?, word(20)?, word(24)?, word(28)?, word(32)?);
    let (scale, device) = (word(48)?, word(52)?);
    let scale = if scale == 0 { 100 } else { scale };
    let fits = |v: u32| u16::try_from(v).ok();
    let size_ok = match (fits(width), fits(height)) {
        (Some(w), Some(h)) => desktop_allowed(w, h, scale),
        _ => false,
    };
    if flags != 1 || left != 0 || top != 0 || !size_ok || !matches!(device, 0 | 100 | 140 | 180) {
        return Err(Refusal("display layout outside the bounds"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ironrdp_core::encode_vec;
    use std::borrow::Cow;

    fn send_data(from_server: bool, channel_id: u16, data: Vec<u8>) -> Vec<u8> {
        let message = if from_server {
            mcs::McsMessage::SendDataIndication(mcs::SendDataIndication {
                initiator_id: 1002,
                channel_id,
                user_data: Cow::Owned(data),
            })
        } else {
            mcs::McsMessage::SendDataRequest(mcs::SendDataRequest {
                initiator_id: 1002,
                channel_id,
                user_data: Cow::Owned(data),
            })
        };
        encode_vec(&X224(message)).expect("mcs")
    }

    /// One whole `drdynvc` message in a single chunk.
    fn chunk(pdu: &[u8]) -> Vec<u8> {
        let mut out = u32::try_from(pdu.len()).expect("small").to_le_bytes().to_vec();
        out.extend_from_slice(&(CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST).to_le_bytes());
        out.extend_from_slice(pdu);
        out
    }

    fn create_request(id: u8, name: &str) -> Vec<u8> {
        [vec![0x10, id], name.as_bytes().to_vec(), vec![0]].concat()
    }

    fn create_response(id: u8, status: i32) -> Vec<u8> {
        [vec![0x10, id], status.to_le_bytes().to_vec()].concat()
    }

    fn data(id: u8, payload: &[u8]) -> Vec<u8> {
        [vec![0x30, id], payload.to_vec()].concat()
    }

    fn layout(width: u32, height: u32, scale: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for w in [2u32, 56, 40, 1, 1, 0, 0, width, height, 300, 200, 0, scale, 100] {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Channels after the Connect Response and Attach User Confirm: I/O 1003,
    /// user 1002, drdynvc 1004.
    fn connected() -> Channels {
        let mut c = Channels::new(vec!["drdynvc".into()], false);
        c.io = Some(1003);
        c.user = Some(1002);
        c.drdynvc = Some(1004);
        c
    }

    fn server(c: &mut Channels, pdu: Vec<u8>) -> Result<(), Refusal> {
        let pass = c.server_pdu(Action::X224, &send_data(true, 1004, chunk(&pdu)))?;
        assert_eq!(pass, Pass::Unchanged, "drdynvc passes as it came");
        Ok(())
    }

    fn browser(c: &mut Channels, pdu: Vec<u8>) -> Result<(), Refusal> {
        let pass = c.browser_pdu(Action::X224, &send_data(false, 1004, chunk(&pdu)))?;
        assert_eq!(pass, Pass::Unchanged, "drdynvc passes as it came");
        Ok(())
    }

    /// Windows' Connect Response numbering `ids` for the requested channels.
    fn connect_response(ids: Vec<u16>) -> Vec<u8> {
        use ironrdp_pdu::gcc::{
            ConferenceCreateResponse, RdpVersion, ServerCoreData, ServerCoreOptionalData, ServerGccBlocks,
            ServerNetworkData, ServerSecurityData,
        };
        let blocks = ServerGccBlocks {
            core: ServerCoreData {
                version: RdpVersion::V5_PLUS,
                optional_data: ServerCoreOptionalData {
                    client_requested_protocols: None,
                    early_capability_flags: None,
                },
            },
            network: ServerNetworkData {
                channel_ids: ids,
                io_channel: 1003,
            },
            security: ServerSecurityData::no_security(),
            message_channel: None,
            multi_transport_channel: None,
        };
        let response = mcs::ConnectResponse {
            conference_create_response: ConferenceCreateResponse::new(1002, blocks).expect("blocks"),
            called_connect_id: 1,
            domain_parameters: mcs::DomainParameters::target(),
        };
        let body = encode_vec(&response).expect("response");
        encode_vec(&X224(X224Data { data: Cow::Owned(body) })).expect("x224")
    }

    #[test]
    fn windows_numbers_exactly_the_channels_asked_for() {
        let mut c = Channels::new(vec!["drdynvc".into()], false);
        c.server_pdu(Action::X224, &connect_response(vec![1004]))
            .expect("one channel, one number");
        assert_eq!((c.io, c.drdynvc), (Some(1003), Some(1004)));
        // drdynvc now carries its messages; another number does not.
        c.server_pdu(Action::X224, &send_data(true, 1004, chunk(&[0x50, 0, 3, 0])))
            .expect("drdynvc");
        assert!(c.server_pdu(Action::X224, &send_data(true, 1005, vec![1])).is_err());
        for (names, ids) in [
            (vec!["drdynvc"], vec![]),
            (vec!["drdynvc"], vec![1004, 1005]),
            (vec![], vec![1004]),
            (vec!["rdpdr"], vec![1004]),
        ] {
            let mut c = Channels::new(names.iter().map(|n| n.to_string()).collect(), false);
            assert!(
                c.server_pdu(Action::X224, &connect_response(ids.clone())).is_err(),
                "{names:?} {ids:?}"
            );
        }
        // With the clipboard allowed, cliprdr is numbered, may be joined, and
        // its messages go through the clipboard filter, gathered and written
        // again. Without it, the same number is refused.
        let mut c = Channels::new(vec!["drdynvc".into(), "cliprdr".into()], true);
        c.server_pdu(Action::X224, &connect_response(vec![1004, 1005]))
            .expect("drdynvc and cliprdr");
        let ready = vec![1, 0, 0, 0, 0, 0, 0, 0];
        let pass = c
            .server_pdu(Action::X224, &send_data(true, 1005, chunk(&ready)))
            .expect("monitor ready");
        assert_eq!(pass, Pass::Instead(vec![send_data(true, 1005, chunk(&ready))]));
        c.user = Some(1002);
        let join = encode_vec(&X224(mcs::McsMessage::ChannelJoinRequest(mcs::ChannelJoinRequest {
            initiator_id: 1002,
            channel_id: 1005,
        })))
        .expect("join");
        assert_eq!(c.browser_pdu(Action::X224, &join), Ok(Pass::Unchanged));
        assert!(
            c.browser_pdu(Action::X224, &send_data(false, 1005, chunk(&ready)))
                .is_err(),
            "monitor ready from the browser"
        );
        let mut c = Channels::new(vec!["drdynvc".into()], false);
        c.server_pdu(Action::X224, &connect_response(vec![1004]))
            .expect("drdynvc");
        assert!(
            c.server_pdu(Action::X224, &send_data(true, 1005, chunk(&ready)))
                .is_err()
        );
        // Without the clipboard, cliprdr is never numbered, even if asked for.
        let mut c = Channels::new(vec!["drdynvc".into(), "cliprdr".into()], false);
        assert!(c.server_pdu(Action::X224, &connect_response(vec![1004, 1005])).is_err());
        // Anything else first is refused.
        let mut c = Channels::new(vec![], false);
        assert!(c.server_pdu(Action::X224, &send_data(true, 1003, vec![1])).is_err());
    }

    #[test]
    fn pdus_are_split_whole_and_bounded() {
        let mut s = Splitter::default();
        let a = send_data(true, 1003, vec![1; 10]);
        let fast = vec![0x00, 0x05, 1, 2, 3];
        let both = [a.clone(), fast.clone()].concat();
        // Byte by byte, then all at once: the same PDUs come out.
        let mut got = Vec::new();
        for b in &both {
            got.extend(s.push(std::slice::from_ref(b)).expect("valid"));
        }
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], (Action::X224, a.clone()));
        assert_eq!(got[1], (Action::FastPath, fast));
        assert_eq!(Splitter::default().push(&both).expect("valid").len(), 2);
        // A TPKT shorter than its header, a fast-path PDU shorter than its own, and nonsense.
        assert!(Splitter::default().push(&[3, 0, 0, 3]).is_err());
        assert!(Splitter::default().push(&[0x00, 0x01]).is_err());
        // A TPKT longer than its own 4-byte header but shorter than TPKT and X.224. Both
        // IronRDP and the size rule above refuse it.
        assert!(Splitter::default().push(&[3, 0, 0, 5, 0]).is_err());
        assert!(Splitter::default().push(&[0x55, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn only_allowed_dynamic_channels_open_and_carry_data() {
        let mut c = connected();
        server(&mut c, vec![0x50, 0x00, 0x03, 0x00]).expect("capabilities");
        // Graphics: Windows asks, the browser opens it, data flows both ways.
        server(&mut c, create_request(3, GRAPHICS)).expect("create graphics");
        browser(&mut c, create_response(3, 0)).expect("open graphics");
        server(&mut c, data(3, &[9; 64])).expect("graphics data");
        browser(&mut c, data(3, &[9; 8])).expect("graphics answer");
        // Anything else: the browser may only refuse it.
        server(&mut c, create_request(4, "rdpdr_dvc")).expect("Windows may ask");
        assert!(
            browser(&mut c, create_response(4, 0)).is_err(),
            "a refused channel was opened"
        );
        let mut c = connected();
        server(&mut c, create_request(4, "Microsoft::Windows::RDS::Geometry::v08.01")).expect("ask");
        browser(&mut c, create_response(4, -1)).expect("refusing is fine");
        assert!(
            server(&mut c, data(4, &[1])).is_err(),
            "data on a refused channel passed"
        );
        assert!(
            browser(&mut c, data(4, &[1])).is_err(),
            "data on a refused channel passed"
        );
        assert!(
            browser(&mut c, data(9, &[1])).is_err(),
            "data on an unknown channel passed"
        );
        // A channel number Windows uses twice, and an answer nobody asked for.
        server(&mut c, create_request(5, GRAPHICS)).expect("ask");
        assert!(server(&mut c, create_request(5, GRAPHICS)).is_err());
        assert!(browser(&mut c, create_response(6, 0)).is_err());
    }

    #[test]
    fn display_layouts_must_be_within_the_bounds() {
        let mut c = connected();
        server(&mut c, create_request(7, DISPLAY)).expect("ask");
        browser(&mut c, create_response(7, 0)).expect("open");
        browser(&mut c, data(7, &layout(1600, 900, 100))).expect("within the bounds");
        browser(&mut c, data(7, &layout(3840, 2160, 200))).expect("200%");
        browser(&mut c, data(7, &layout(1600, 900, 0))).expect("no scale reads as 100%");
        for (what, bad) in [
            ("too wide", layout(1922, 1080, 100)),
            ("odd", layout(1601, 900, 100)),
            ("4K at 100%", layout(3840, 2160, 100)),
            ("110%", layout(1600, 900, 110)),
            ("cut", layout(1600, 900, 100)[..50].to_vec()),
        ] {
            assert!(browser(&mut c, data(7, &bad)).is_err(), "{what}");
        }
        let mut two = layout(1600, 900, 100);
        two[12] = 2;
        assert!(browser(&mut c, data(7, &two)).is_err(), "two monitors");
        // Windows' own messages on the channel are not layouts.
        server(&mut c, data(7, &[5, 0, 0, 0, 20, 0, 0, 0])).expect("Windows' capabilities");
        // A layout split over chunks is refused.
        assert!(browser(&mut c, [vec![0x20, 7, 56], layout(1600, 900, 100)].concat()).is_err());
    }

    #[test]
    fn static_channels_and_chunks_follow_the_rules() {
        let mut c = connected();
        // I/O and user channels pass; others do not.
        c.server_pdu(Action::X224, &send_data(true, 1003, vec![1, 2]))
            .expect("I/O");
        c.browser_pdu(Action::X224, &send_data(false, 1002, vec![1, 2]))
            .expect("user");
        assert!(c.server_pdu(Action::X224, &send_data(true, 1007, vec![1])).is_err());
        assert!(c.browser_pdu(Action::X224, &send_data(false, 1007, vec![1])).is_err());
        let join = |id| {
            encode_vec(&X224(mcs::McsMessage::ChannelJoinRequest(mcs::ChannelJoinRequest {
                initiator_id: 1002,
                channel_id: id,
            })))
            .expect("join")
        };
        c.browser_pdu(Action::X224, &join(1004)).expect("drdynvc");
        assert!(
            c.browser_pdu(Action::X224, &join(1005)).is_err(),
            "an unknown channel joined"
        );
        // Chunks: a first inside a message, a middle outside one, compression.
        let first = |flags: u32| {
            let mut out = 100u32.to_le_bytes().to_vec();
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&create_request(3, GRAPHICS));
            send_data(true, 1004, out)
        };
        c.server_pdu(Action::X224, &first(CHANNEL_FLAG_FIRST))
            .expect("first of two");
        assert!(c.server_pdu(Action::X224, &first(CHANNEL_FLAG_FIRST)).is_err());
        let mut c = connected();
        assert!(c.server_pdu(Action::X224, &first(0)).is_err(), "a middle chunk alone");
        assert!(
            c.server_pdu(
                Action::X224,
                &first(CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST | CHANNEL_PACKET_COMPRESSED)
            )
            .is_err()
        );
        // Soft-sync and unknown commands.
        assert!(server(&mut connected(), vec![0x80, 0, 0, 0]).is_err());
        assert!(server(&mut connected(), vec![0xf0, 1]).is_err());
        // Fast-path passes both ways.
        c.server_pdu(Action::FastPath, &[0, 3, 0]).expect("output");
        c.browser_pdu(Action::FastPath, &[0, 3, 0]).expect("input");
    }

    /// A Client Info as a browser could write it: someone else's name, a
    /// password, and optionally an auto-reconnect cookie.
    pub(crate) fn client_info(
        shell: &str,
        dir: &str,
        flags: ironrdp_pdu::rdp::client_info::ClientInfoFlags,
        cookie: bool,
    ) -> Vec<u8> {
        use ironrdp_pdu::rdp::client_info::{
            AddressFamily, ClientInfo, CompressionType, Credentials, ExtendedClientInfo, ExtendedClientOptionalInfo,
            OptionalSystemTime, PasswordCookie, PerformanceFlags, TimezoneInfo,
        };
        use ironrdp_pdu::rdp::headers::{BasicSecurityHeader, BasicSecurityHeaderFlags};
        let timezone = TimezoneInfo {
            bias: -240,
            standard_name: "Azerbaijan Standard Time".into(),
            standard_date: OptionalSystemTime(None),
            standard_bias: 0,
            daylight_name: String::new(),
            daylight_date: OptionalSystemTime(None),
            daylight_bias: 0,
        };
        let optional = ExtendedClientOptionalInfo::builder()
            .timezone(timezone)
            .session_id(0)
            .performance_flags(PerformanceFlags::DISABLE_WALLPAPER);
        let optional = if cookie {
            optional.reconnect_cookie([7; 28]).build()
        } else {
            optional.build()
        };
        let pdu = ironrdp_pdu::rdp::ClientInfoPdu {
            security_header: BasicSecurityHeader {
                flags: BasicSecurityHeaderFlags::INFO_PKT,
            },
            client_info: ClientInfo {
                credentials: Credentials {
                    username: "someone-else".into(),
                    password: "not-for-windows".into(),
                    domain: Some("ELSEWHERE".into()),
                },
                // Invalid as text, so it decodes as a redirection cookie.
                password_cookie: cookie.then(|| PasswordCookie(vec![0x00, 0xD8, 0x41, 0x00])),
                code_page: 0,
                flags,
                compression_type: CompressionType::K8,
                alternate_shell: shell.into(),
                work_dir: dir.into(),
                extra_info: ExtendedClientInfo {
                    address_family: AddressFamily::from_u16(2),
                    address: "127.0.0.1".into(),
                    dir: "C:\\Windows\\System32\\mstscax.dll".into(),
                    optional_data: optional,
                },
            },
        };
        encode_vec(&pdu).expect("client info")
    }

    fn written_client_info(pass: Result<Pass, Refusal>) -> ironrdp_pdu::rdp::ClientInfoPdu {
        let Ok(Pass::Instead(pdus)) = pass else {
            panic!("the Client Info was not written again: {pass:?}");
        };
        assert_eq!(pdus.len(), 1);
        let X224(mcs::McsMessage::SendDataRequest(data)) = decode::<X224<mcs::McsMessage<'_>>>(&pdus[0]).expect("mcs")
        else {
            panic!("not channel data");
        };
        assert_eq!((data.initiator_id, data.channel_id), (1002, 1003));
        decode::<ironrdp_pdu::rdp::ClientInfoPdu>(&data.user_data).expect("client info")
    }

    #[test]
    fn the_client_info_names_the_account_and_asks_for_nothing_more() {
        use ironrdp_pdu::rdp::client_info::{ClientInfoFlags, PerformanceFlags};
        let normal = ClientInfoFlags::MOUSE | ClientInfoFlags::UNICODE | ClientInfoFlags::DISABLE_CTRL_ALT_DEL;
        let first = |c: &mut Channels, pdu: Vec<u8>| c.browser_pdu(Action::X224, &send_data(false, 1003, pdu));

        // Written again: the account, no password, no cookie; the rest kept.
        let mut c = connected().for_account("kb-user", "KB");
        let sent = decode::<ironrdp_pdu::rdp::ClientInfoPdu>(&client_info("", "", normal, true)).expect("decodes");
        assert!(
            sent.client_info.password_cookie.is_some(),
            "the test sends a redirection cookie"
        );
        assert!(sent.client_info.extra_info.optional_data.reconnect_cookie().is_some());
        let written = written_client_info(first(&mut c, client_info("", "", normal, true)));
        let info = written.client_info;
        assert_eq!(info.credentials.username, "kb-user");
        assert_eq!(info.credentials.domain.as_deref(), Some("KB"));
        assert_eq!(info.credentials.password, "");
        assert!(info.password_cookie.is_none());
        assert!(info.extra_info.optional_data.reconnect_cookie().is_none());
        assert_eq!(info.extra_info.optional_data.timezone().map(|t| t.bias), Some(-240));
        assert_eq!(
            info.extra_info.optional_data.performance_flags(),
            Some(PerformanceFlags::DISABLE_WALLPAPER)
        );
        assert_eq!(info.flags, normal);
        // Only the first: later I/O data passes as it came.
        assert_eq!(first(&mut c, vec![1, 2, 3]), Ok(Pass::Unchanged));

        // An empty domain is none.
        let mut c = connected().for_account("kb-user", "");
        let written = written_client_info(first(&mut c, client_info("", "", normal, false)));
        assert_eq!(written.client_info.credentials.domain, None);

        // A program instead of the desktop, a working folder, RemoteApp,
        // anything that is not a Client Info, or no account: refused.
        for bad in [
            client_info("cmd.exe", "", normal, false),
            client_info("", "C:\\", normal, false),
            client_info("", "", normal | ClientInfoFlags::RAIL, false),
            vec![1, 2, 3],
        ] {
            let mut c = connected().for_account("kb-user", "");
            assert!(first(&mut c, bad).is_err());
        }
        let mut other_header = client_info("", "", normal, false);
        other_header[0] |= 0x08; // SEC_ENCRYPT beside SEC_INFO_PKT (0x0040)
        assert!(first(&mut connected().for_account("kb-user", ""), other_header).is_err());
        assert!(first(&mut connected(), client_info("", "", normal, false)).is_err());
    }
}
