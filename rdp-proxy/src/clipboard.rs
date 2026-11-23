//! The clipboard through the proxy (docs/BROWSER-RDP-PROXY.md, 2c): text
//! only, within the gateway's own limits. Every `cliprdr` message is gathered
//! whole, checked and written again; nothing passes as it came.
//!
//! - Capabilities keep only long format names: no files, no locks.
//! - A format list keeps only Unicode text.
//! - A side may ask only for Unicode text, and data passes only to a side that
//!   asked for it.
//! - Data passes only from a side whose latest list offered text, as valid
//!   text of at most 32 KiB in UTF-8, paced as the gateway paces it. Otherwise
//!   the side that asked gets a failure, and the session goes on.
//! - Files, locks and the temporary directory never pass.
//! - Nothing from the browser passes before Windows' clipboard is open.
//!
//! Anything malformed ends the session as "refused".

use std::borrow::Cow;
use std::time::Instant;

use ironrdp_core::encode_vec;
use ironrdp_pdu::mcs;
use ironrdp_pdu::x224::X224;

use crate::refusal::Refusal;

/// Text crossing the clipboard, measured in UTF-8: the gateway's own limit.
pub const MAX_TEXT: usize = 32 * 1024;
/// The largest message kept whole: a text response at the limit, as UTF-16
/// with its NUL. A larger text response is counted, not kept.
const MAX_MESSAGE: usize = 8 + 2 * MAX_TEXT + 2;
/// The largest message counted at all, chunks together.
const MAX_COUNTED: usize = 16 * 1024 * 1024;
/// Data requests a side may have waiting: IronRDP's own limit.
const MAX_PENDING: usize = 64;
/// Completed transfers in each direction: a burst, then one a second, as the
/// gateway's clipboard (internal/rdplab/pace.go).
const BURST: f64 = 128.0;
const PER_SECOND: f64 = 1.0;
/// The chunk size every RDP peer accepts (MS-RDPBCGR, CHANNEL_CHUNK_LENGTH).
const CHUNK: usize = 1600;

const CF_UNICODETEXT: u32 = 13;
const USE_LONG_FORMAT_NAMES: u32 = 0x02;

// Static virtual channel chunk flags (MS-RDPBCGR 2.2.6.1.1).
const FIRST: u32 = 0x01;
const LAST: u32 = 0x02;
const SHOW_PROTOCOL: u32 = 0x10;

// Clipboard message types and flags (MS-RDPECLIP 2.2.1).
const MONITOR_READY: u16 = 0x0001;
const FORMAT_LIST: u16 = 0x0002;
const FORMAT_LIST_RESPONSE: u16 = 0x0003;
const FORMAT_DATA_REQUEST: u16 = 0x0004;
const FORMAT_DATA_RESPONSE: u16 = 0x0005;
const TEMPORARY_DIRECTORY: u16 = 0x0006;
const CAPABILITIES: u16 = 0x0007;
const RESPONSE_OK: u16 = 0x0001;
const RESPONSE_FAIL: u16 = 0x0002;
const ASCII_NAMES: u16 = 0x0004;

/// A message being gathered from one side.
struct Gathering {
    total: usize,
    show_protocol: bool,
    received: usize,
    data: Vec<u8>,
    /// A text response over the limit: its bytes are counted, not kept.
    oversize: bool,
}

/// A whole message from one side.
enum Whole {
    Message(Vec<u8>),
    OversizeText,
}

/// What one side has said so far.
#[derive(Default)]
struct Side {
    capabilities: bool,
    long_names: bool,
    offers_text: bool,
    /// Data requests this side sent that are not answered yet.
    pending: usize,
    gathering: Option<Gathering>,
    debt: f64,
    paced_at: Option<Instant>,
}

impl Side {
    /// Spends one transfer from this side's budget, if it has one.
    fn pace(&mut self, now: Instant) -> bool {
        if let Some(at) = self.paced_at {
            let refill = now.saturating_duration_since(at).as_secs_f64() * PER_SECOND;
            self.debt = (self.debt - refill).max(0.0);
        }
        self.paced_at = Some(now);
        if self.debt + 1.0 > BURST {
            return false;
        }
        self.debt += 1.0;
        true
    }
}

#[derive(Default)]
pub struct Clipboard {
    server: Side,
    browser: Side,
    /// Windows' clipboard is open: it has sent its Monitor Ready, after which
    /// the browser's clipboard may speak (MS-RDPECLIP 1.3.2.1).
    open: bool,
}

impl Clipboard {
    /// One `cliprdr` chunk from Windows or from the browser. Returns the MCS
    /// PDUs that go on in its place: none until its message is whole, then
    /// the checked message, written again in chunks.
    pub fn chunk(
        &mut self,
        from_server: bool,
        initiator: u16,
        channel: u16,
        chunk: &[u8],
        now: Instant,
    ) -> Result<Vec<Vec<u8>>, Refusal> {
        let Some((show_protocol, whole)) = self.gather(from_server, chunk)? else {
            return Ok(Vec::new());
        };
        match self.message(from_server, whole, now)? {
            Some(message) => encode(from_server, initiator, channel, show_protocol, &message),
            None => Ok(Vec::new()),
        }
    }

    fn gather(&mut self, from_server: bool, chunk: &[u8]) -> Result<Option<(bool, Whole)>, Refusal> {
        let side = if from_server {
            &mut self.server
        } else {
            &mut self.browser
        };
        let total = usize::try_from(u32_at(chunk, 0)?).map_err(|_| Refusal::ClipboardChunk)?;
        let flags = u32_at(chunk, 4)?;
        let body = &chunk[8..];
        if flags & !(FIRST | LAST | SHOW_PROTOCOL) != 0 || body.is_empty() {
            return Err(Refusal::ClipboardChunk);
        }
        if flags & FIRST != 0 {
            if side.gathering.is_some() || !(8..=MAX_COUNTED).contains(&total) {
                return Err(Refusal::ClipboardChunkOrder);
            }
            let oversize = total > MAX_MESSAGE;
            // Only a text response may be larger than a message is kept, and
            // its header must say so in the first chunk.
            if oversize
                && (u16_at(body, 0)? != FORMAT_DATA_RESPONSE
                    || u16_at(body, 2)? != RESPONSE_OK
                    || usize::try_from(u32_at(body, 4)?).ok() != Some(total - 8))
            {
                return Err(Refusal::ClipboardTooLarge);
            }
            side.gathering = Some(Gathering {
                total,
                show_protocol: flags & SHOW_PROTOCOL != 0,
                received: 0,
                data: Vec::new(),
                oversize,
            });
        }
        let gathering = side.gathering.as_mut().ok_or(Refusal::ClipboardChunkOrder)?;
        if total != gathering.total || (flags & SHOW_PROTOCOL != 0) != gathering.show_protocol {
            return Err(Refusal::ClipboardChunk);
        }
        gathering.received += body.len();
        if gathering.received > gathering.total {
            return Err(Refusal::ClipboardChunk);
        }
        if !gathering.oversize {
            gathering.data.extend_from_slice(body);
        }
        let done = gathering.received == gathering.total;
        if done != (flags & LAST != 0) {
            return Err(Refusal::ClipboardChunkOrder);
        }
        if !done {
            return Ok(None);
        }
        let Some(whole) = side.gathering.take() else {
            return Err(Refusal::ClipboardChunkOrder);
        };
        let message = if whole.oversize {
            Whole::OversizeText
        } else {
            Whole::Message(whole.data)
        };
        Ok(Some((whole.show_protocol, message)))
    }

    /// Checks one whole message and returns what goes on in its place.
    fn message(&mut self, from_server: bool, whole: Whole, now: Instant) -> Result<Option<Vec<u8>>, Refusal> {
        let long = self.server.long_names && self.browser.long_names;
        let (me, other) = if from_server {
            (&mut self.server, &mut self.browser)
        } else {
            (&mut self.browser, &mut self.server)
        };
        let message = match whole {
            Whole::Message(message) => message,
            Whole::OversizeText => {
                asked(other)?;
                return written(FORMAT_DATA_RESPONSE, RESPONSE_FAIL, &[]).map(Some);
            }
        };
        let (kind, flags) = (u16_at(&message, 0)?, u16_at(&message, 2)?);
        let body = &message[8..];
        if usize::try_from(u32_at(&message, 4)?).ok() != Some(body.len()) {
            return Err(Refusal::ClipboardLength);
        }
        if !from_server && !self.open {
            return before_open(kind, flags, body);
        }
        match kind {
            CAPABILITIES => {
                if !general_set(flags, body)? || me.capabilities {
                    return Err(Refusal::ClipboardCapabilities);
                }
                let general = u32_at(body, 12)? & USE_LONG_FORMAT_NAMES;
                me.capabilities = true;
                me.long_names = general != 0;
                let mut out = body[..12].to_vec();
                out.extend_from_slice(&general.to_le_bytes());
                written(CAPABILITIES, 0, &out).map(Some)
            }
            MONITOR_READY if from_server && flags == 0 && body.is_empty() => {
                self.open = true;
                Ok(Some(message))
            }
            FORMAT_LIST => {
                if flags & !ASCII_NAMES != 0 {
                    return Err(Refusal::ClipboardFormatList);
                }
                me.offers_text = offers_text(body, long, flags & ASCII_NAMES != 0)?;
                let mut out = Vec::new();
                if me.offers_text {
                    out.extend_from_slice(&CF_UNICODETEXT.to_le_bytes());
                    // The name: empty, as a NUL in long form, or the fixed 32 bytes.
                    out.resize(if long { 4 + 2 } else { 4 + 32 }, 0);
                }
                written(FORMAT_LIST, 0, &out).map(Some)
            }
            FORMAT_LIST_RESPONSE if body.is_empty() && matches!(flags, RESPONSE_OK | RESPONSE_FAIL) => {
                Ok(Some(message))
            }
            FORMAT_DATA_REQUEST => {
                if flags != 0 || body.len() != 4 || u32_at(body, 0)? != CF_UNICODETEXT {
                    return Err(Refusal::ClipboardNotText);
                }
                if me.pending >= MAX_PENDING {
                    return Err(Refusal::ClipboardUnanswered);
                }
                me.pending += 1;
                Ok(Some(message))
            }
            FORMAT_DATA_RESPONSE => {
                asked(other)?;
                match flags {
                    RESPONSE_FAIL if body.is_empty() => Ok(Some(message)),
                    RESPONSE_OK => {
                        let passed = if me.offers_text { text(body) } else { None };
                        match passed {
                            Some(text) if me.pace(now) => written(FORMAT_DATA_RESPONSE, RESPONSE_OK, &text).map(Some),
                            _ => written(FORMAT_DATA_RESPONSE, RESPONSE_FAIL, &[]).map(Some),
                        }
                    }
                    _ => Err(Refusal::ClipboardResponse),
                }
            }
            // The browser's temporary directory is for files; Windows never hears it.
            TEMPORARY_DIRECTORY if !from_server && flags == 0 && body.len() == 520 => Ok(None),
            _ => Err(Refusal::ClipboardNotAllowed),
        }
    }
}

/// A browser message before Windows' clipboard is open. Windows speaks first,
/// and its clipboard may never open: rdpclip can stop answering a session.
/// IronRDP still sends its capabilities, temporary directory and format list
/// with the first paste, and again with each paste until Windows answers.
/// Those three are checked as far as they can be and dropped, so the paste
/// fails on the page and the desktop goes on. Nothing is recorded: they come
/// again once Windows' clipboard opens. Anything else ends the session.
fn before_open(kind: u16, flags: u16, body: &[u8]) -> Result<Option<Vec<u8>>, Refusal> {
    match kind {
        CAPABILITIES if general_set(flags, body)? => Ok(None),
        CAPABILITIES => Err(Refusal::ClipboardCapabilities),
        // Long or short names depend on Windows' capabilities; it is not read.
        FORMAT_LIST if flags & !ASCII_NAMES == 0 => Ok(None),
        TEMPORARY_DIRECTORY if flags == 0 && body.len() == 520 => Ok(None),
        _ => Err(Refusal::ClipboardBeforeOpen),
    }
}

/// One general capability set: count, pad, type, length, version, flags.
fn general_set(flags: u16, body: &[u8]) -> Result<bool, Refusal> {
    Ok(flags == 0
        && body.len() == 16
        && u16_at(body, 0)? == 1
        && u16_at(body, 4)? == 1
        && u16_at(body, 6)? == 12
        && matches!(u32_at(body, 8)?, 1 | 2))
}

/// A response must answer a request the other side is waiting on.
fn asked(asker: &mut Side) -> Result<(), Refusal> {
    asker.pending = asker.pending.checked_sub(1).ok_or(Refusal::ClipboardUnasked)?;
    Ok(())
}

/// Whether a format list offers Unicode text (MS-RDPECLIP 2.2.3.1).
fn offers_text(body: &[u8], long: bool, ascii: bool) -> Result<bool, Refusal> {
    let mut text = false;
    if long {
        if ascii {
            return Err(Refusal::ClipboardFormatList);
        }
        let mut rest = body;
        while !rest.is_empty() {
            let id = u32_at(rest, 0)?;
            rest = &rest[4..];
            // The name is UTF-16, up to and including its NUL.
            let end = rest
                .chunks_exact(2)
                .position(|unit| unit == [0, 0])
                .ok_or(Refusal::ClipboardFormatName)?;
            rest = &rest[2 * end + 2..];
            text |= id == CF_UNICODETEXT;
        }
    } else {
        if !body.len().is_multiple_of(36) {
            return Err(Refusal::ClipboardFormatList);
        }
        for entry in body.chunks_exact(36) {
            text |= u32_at(entry, 0)? == CF_UNICODETEXT;
        }
    }
    Ok(text)
}

/// Unicode text as it passes: valid UTF-16 up to its first NUL, at most
/// `MAX_TEXT` bytes as UTF-8, written again with one NUL. `None` if it is not.
fn text(data: &[u8]) -> Option<Vec<u8>> {
    if !data.len().is_multiple_of(2) {
        return None;
    }
    let units = data
        .chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .take_while(|&unit| unit != 0);
    let text: String = char::decode_utf16(units).collect::<Result<_, _>>().ok()?;
    if text.len() > MAX_TEXT {
        return None;
    }
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    Some(out)
}

/// A clipboard message: type, flags, length and body.
fn written(kind: u16, flags: u16, body: &[u8]) -> Result<Vec<u8>, Refusal> {
    let length = u32::try_from(body.len()).map_err(|_| Refusal::ClipboardMessage)?;
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// A message in chunks of at most `CHUNK` bytes, each in its own MCS PDU, as
/// the side it came from would send it.
fn encode(
    from_server: bool,
    initiator: u16,
    channel: u16,
    show_protocol: bool,
    message: &[u8],
) -> Result<Vec<Vec<u8>>, Refusal> {
    let total = u32::try_from(message.len()).map_err(|_| Refusal::ClipboardMessage)?;
    let parts: Vec<&[u8]> = message.chunks(CHUNK).collect();
    let mut out = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        let mut flags = if show_protocol { SHOW_PROTOCOL } else { 0 };
        if i == 0 {
            flags |= FIRST;
        }
        if i + 1 == parts.len() {
            flags |= LAST;
        }
        let mut data = Vec::with_capacity(8 + part.len());
        data.extend_from_slice(&total.to_le_bytes());
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(part);
        let user_data = Cow::Owned(data);
        let pdu = if from_server {
            mcs::McsMessage::SendDataIndication(mcs::SendDataIndication {
                initiator_id: initiator,
                channel_id: channel,
                user_data,
            })
        } else {
            mcs::McsMessage::SendDataRequest(mcs::SendDataRequest {
                initiator_id: initiator,
                channel_id: channel,
                user_data,
            })
        };
        out.push(encode_vec(&X224(pdu)).map_err(|_| Refusal::ClipboardMessage)?);
    }
    Ok(out)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, Refusal> {
    let b = bytes.get(at..at + 2).ok_or(Refusal::ClipboardMessage)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, Refusal> {
    let b = bytes.get(at..at + 4).ok_or(Refusal::ClipboardMessage)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ironrdp_cliprdr::pdu::{
        Capabilities, ClientTemporaryDirectory, ClipboardFormat, ClipboardFormatId, ClipboardFormatName,
        ClipboardGeneralCapabilityFlags, ClipboardPdu, ClipboardProtocolVersion, FileContentsFlags,
        FileContentsRequest, FormatDataRequest, FormatDataResponse, FormatList, FormatListResponse, LockDataId,
    };
    use ironrdp_core::decode;
    use std::time::Duration;

    const IO: u16 = 1003;
    const CLIP: u16 = 1005;

    fn pdu(p: &ClipboardPdu<'_>) -> Vec<u8> {
        encode_vec(p).expect("clipboard pdu")
    }

    /// Sends one message through in chunks of `size`, then reads back what
    /// the proxy passed on: the whole message, or `None` if nothing passed.
    fn through(
        clip: &mut Clipboard,
        from_server: bool,
        message: &[u8],
        size: usize,
        now: Instant,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let parts: Vec<&[u8]> = message.chunks(size).collect();
        let mut out = Vec::new();
        for (i, part) in parts.iter().enumerate() {
            let mut flags = SHOW_PROTOCOL;
            if i == 0 {
                flags |= FIRST;
            }
            if i + 1 == parts.len() {
                flags |= LAST;
            }
            let mut chunk = u32::try_from(message.len()).expect("small").to_le_bytes().to_vec();
            chunk.extend_from_slice(&flags.to_le_bytes());
            chunk.extend_from_slice(part);
            let passed = clip.chunk(from_server, IO, CLIP, &chunk, now)?;
            if i + 1 < parts.len() {
                assert!(passed.is_empty(), "a message passed before it was whole");
            }
            out = passed;
        }
        Ok(reassemble(from_server, &out))
    }

    /// The message inside MCS PDUs the proxy wrote, checking their chunks.
    fn reassemble(from_server: bool, pdus: &[Vec<u8>]) -> Option<Vec<u8>> {
        let mut message = Vec::new();
        for (i, p) in pdus.iter().enumerate() {
            let X224(mcs) = decode::<X224<mcs::McsMessage<'_>>>(p).expect("MCS");
            let data = match (mcs, from_server) {
                (mcs::McsMessage::SendDataIndication(d), true) => d.user_data.into_owned(),
                (mcs::McsMessage::SendDataRequest(d), false) => d.user_data.into_owned(),
                _ => panic!("the wrong MCS PDU for the direction"),
            };
            let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
            assert!(data.len() <= 8 + CHUNK, "a chunk over 1600 bytes");
            assert_eq!(flags & FIRST != 0, i == 0);
            assert_eq!(flags & LAST != 0, i + 1 == pdus.len());
            assert_ne!(flags & SHOW_PROTOCOL, 0, "show-protocol kept");
            message.extend_from_slice(&data[8..]);
        }
        (!pdus.is_empty()).then_some(message)
    }

    fn caps(flags: ClipboardGeneralCapabilityFlags) -> Vec<u8> {
        pdu(&ClipboardPdu::Capabilities(Capabilities::new(
            ClipboardProtocolVersion::V2,
            flags,
        )))
    }

    /// Both sides have said everything IronRDP and Windows say, in their
    /// order: Windows' capabilities and Monitor Ready, then the browser's.
    fn opened(flags: ClipboardGeneralCapabilityFlags, now: Instant) -> Clipboard {
        let mut clip = Clipboard::default();
        through(&mut clip, true, &caps(flags), CHUNK, now).expect("server caps");
        through(&mut clip, true, &pdu(&ClipboardPdu::MonitorReady), CHUNK, now).expect("monitor ready");
        through(&mut clip, false, &caps(flags), CHUNK, now).expect("client caps");
        clip
    }

    /// Long names, as IronRDP and Windows agree.
    fn ready(now: Instant) -> Clipboard {
        opened(ClipboardGeneralCapabilityFlags::all(), now)
    }

    fn list(formats: &[ClipboardFormat], long: bool) -> Vec<u8> {
        pdu(&ClipboardPdu::FormatList(
            FormatList::new_unicode(formats, long).expect("format list"),
        ))
    }

    fn rich() -> Vec<ClipboardFormat> {
        vec![
            ClipboardFormat::new(ClipboardFormatId::new(1)),
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
            ClipboardFormat::new(ClipboardFormatId::new(0xC0F1)).with_name(ClipboardFormatName::new("HTML Format")),
            ClipboardFormat::new(ClipboardFormatId::new(0xC0F2))
                .with_name(ClipboardFormatName::new("FileGroupDescriptorW")),
        ]
    }

    fn formats_of(message: &[u8], long: bool) -> Vec<u32> {
        let ClipboardPdu::FormatList(list) = decode::<ClipboardPdu<'_>>(message).expect("decodes") else {
            panic!("not a format list");
        };
        list.get_formats(long)
            .expect("formats")
            .iter()
            .map(|f| f.id().value())
            .collect()
    }

    fn request() -> Vec<u8> {
        pdu(&ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::CF_UNICODETEXT,
        }))
    }

    fn response(data: Vec<u8>) -> Vec<u8> {
        pdu(&ClipboardPdu::FormatDataResponse(FormatDataResponse::new_data(data)))
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn text_of(message: &[u8]) -> Option<String> {
        let ClipboardPdu::FormatDataResponse(r) = decode::<ClipboardPdu<'_>>(message).expect("decodes") else {
            panic!("not a data response");
        };
        (!r.is_error()).then(|| r.to_unicode_string().expect("text"))
    }

    #[test]
    fn capabilities_keep_only_long_names() {
        let now = Instant::now();
        let mut clip = Clipboard::default();
        let out = through(&mut clip, true, &caps(ClipboardGeneralCapabilityFlags::all()), 5, now)
            .expect("caps")
            .expect("passed");
        let ClipboardPdu::Capabilities(passed) = decode::<ClipboardPdu<'_>>(&out).expect("decodes") else {
            panic!("not capabilities");
        };
        assert_eq!(passed.flags(), ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
        // Once per side, and only the one well-formed general set.
        assert!(
            through(
                &mut clip,
                true,
                &caps(ClipboardGeneralCapabilityFlags::empty()),
                CHUNK,
                now
            )
            .is_err()
        );
        let good = caps(ClipboardGeneralCapabilityFlags::empty());
        for (at, value) in [(8, 2u8), (12, 2), (14, 11), (16, 3)] {
            let mut bad = good.clone();
            bad[at] = value;
            assert!(
                through(&mut Clipboard::default(), false, &bad, CHUNK, now).is_err(),
                "byte {at} = {value}"
            );
        }
        let mut flagged = good.clone();
        flagged[2] = 1;
        assert!(through(&mut Clipboard::default(), false, &flagged, CHUNK, now).is_err());
    }

    #[test]
    fn format_lists_keep_only_text() {
        let now = Instant::now();
        let mut clip = ready(now);
        let out = through(&mut clip, true, &list(&rich(), true), 7, now)
            .expect("list")
            .expect("passed");
        assert_eq!(formats_of(&out, true), vec![13]);
        let none = [ClipboardFormat::new(ClipboardFormatId::new(1))];
        let out = through(&mut clip, false, &list(&none, true), CHUNK, now)
            .expect("list")
            .expect("passed");
        assert!(formats_of(&out, true).is_empty());

        // Short names when either side lacks long names.
        let mut short = opened(ClipboardGeneralCapabilityFlags::empty(), now);
        // Short names hold at most 15 UTF-16 characters and a NUL.
        let short_named = [
            ClipboardFormat::new(ClipboardFormatId::new(7)),
            ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
            ClipboardFormat::new(ClipboardFormatId::new(0xC0F1)).with_name(ClipboardFormatName::new("HTML Format")),
            ClipboardFormat::new(ClipboardFormatId::new(0xC0F3)).with_name(ClipboardFormatName::new("FileNameW")),
        ];
        let out = through(&mut short, true, &list(&short_named, false), CHUNK, now)
            .expect("list")
            .expect("passed");
        assert_eq!(formats_of(&out, false), vec![13]);

        // A name without its NUL, a short list of the wrong size, other flags.
        let relength = |m: &mut Vec<u8>| {
            let length = u32::try_from(m.len() - 8).expect("small").to_le_bytes();
            m[4..8].copy_from_slice(&length);
        };
        let mut cut = list(&rich(), true);
        cut.truncate(cut.len() - 2);
        relength(&mut cut);
        assert!(through(&mut ready(now), true, &cut, CHUNK, now).is_err());
        let mut odd = list(&short_named, false);
        odd.push(0);
        relength(&mut odd);
        assert!(through(&mut short, true, &odd, CHUNK, now).is_err());
        let mut flagged = list(&rich(), true);
        flagged[2] = 0x04;
        assert!(through(&mut ready(now), true, &flagged, CHUNK, now).is_err());
    }

    #[test]
    fn text_passes_only_when_asked_for_and_offered() {
        let now = Instant::now();
        let mut clip = ready(now);
        // Windows offers text; the browser asks; the text passes, written again.
        through(&mut clip, true, &list(&rich(), true), CHUNK, now).expect("list");
        let asked = through(&mut clip, false, &request(), CHUNK, now).expect("request");
        assert_eq!(asked.as_deref(), Some(&request()[..]));
        let mut data = utf16("héllo, wörld 🙂");
        data.extend_from_slice(&[0, 0, 0x41, 0, 0, 0]);
        let out = through(&mut clip, true, &response(data), 9, now)
            .expect("response")
            .expect("passed");
        assert_eq!(text_of(&out).as_deref(), Some("héllo, wörld 🙂"));

        // Data nobody asked for ends the session.
        assert!(through(&mut clip, true, &response(utf16("x")), CHUNK, now).is_err());
        // Any format but text ends the session.
        let html = pdu(&ClipboardPdu::FormatDataRequest(FormatDataRequest {
            format: ClipboardFormatId::new(0xC0F1),
        }));
        assert!(through(&mut ready(now), false, &html, CHUNK, now).is_err());

        // Text that is not valid, too long, or from a side that offered none: a failure, and the session goes on.
        let lone = vec![0x00, 0xD8, 0x41, 0x00];
        let over = utf16(&"€".repeat(MAX_TEXT / 3 + 1));
        let at_limit = utf16(&"€".repeat(MAX_TEXT / 3));
        for (data, passes) in [(lone, false), (vec![0x41], false), (over, false), (at_limit, true)] {
            through(&mut clip, false, &request(), CHUNK, now).expect("request");
            let out = through(&mut clip, true, &response(data), CHUNK, now)
                .expect("response")
                .expect("passed");
            assert_eq!(text_of(&out).is_some(), passes);
        }
        through(&mut clip, true, &list(&[], true), CHUNK, now).expect("list");
        through(&mut clip, false, &request(), CHUNK, now).expect("request");
        let out = through(&mut clip, true, &response(utf16("x")), CHUNK, now)
            .expect("response")
            .expect("passed");
        assert_eq!(text_of(&out), None);
        // A failure passes as a failure.
        through(&mut clip, false, &request(), CHUNK, now).expect("request");
        let fail = pdu(&ClipboardPdu::FormatDataResponse(FormatDataResponse::new_error()));
        let out = through(&mut clip, true, &fail, CHUNK, now)
            .expect("fail")
            .expect("passed");
        assert_eq!(out, fail);
    }

    #[test]
    fn large_text_is_counted_not_kept() {
        let now = Instant::now();
        let mut clip = ready(now);
        through(&mut clip, true, &list(&rich(), true), CHUNK, now).expect("list");
        through(&mut clip, false, &request(), CHUNK, now).expect("request");
        let big = response(vec![0x41; 3 * MAX_MESSAGE]);
        // After its first chunk nothing of it is kept, only counted.
        let mut first = u32::try_from(big.len()).expect("small").to_le_bytes().to_vec();
        first.extend_from_slice(&FIRST.to_le_bytes());
        first.extend_from_slice(&big[..CHUNK]);
        let mut probe = ready(now);
        through(&mut probe, true, &list(&rich(), true), CHUNK, now).expect("list");
        through(&mut probe, false, &request(), CHUNK, now).expect("request");
        assert!(probe.chunk(true, IO, CLIP, &first, now).expect("first").is_empty());
        let gathering = probe.server.gathering.as_ref().expect("gathering");
        assert!(gathering.oversize && gathering.data.is_empty(), "kept, not counted");
        // Whole, the asker gets a failure.
        let out = through(&mut clip, true, &big, CHUNK, now)
            .expect("big")
            .expect("passed");
        assert_eq!(text_of(&out), None);
        assert!(clip.server.gathering.is_none());
        // Unasked, it still ends the session.
        assert!(through(&mut clip, true, &big, CHUNK, now).is_err());
        // Only a text response may be that large: not even a well-formed list.
        let many: Vec<ClipboardFormat> = (0..4000u32)
            .map(|i| {
                ClipboardFormat::new(ClipboardFormatId::new(0xC000 + i))
                    .with_name(ClipboardFormatName::new(format!("Format {i}")))
            })
            .collect();
        let list_big = list(&many, true);
        assert!(list_big.len() > MAX_MESSAGE);
        assert!(through(&mut ready(now), true, &list_big, CHUNK, now).is_err());
    }

    #[test]
    fn files_locks_and_directories_never_pass() {
        let now = Instant::now();
        let directory = pdu(&ClipboardPdu::TemporaryDirectory(
            ClientTemporaryDirectory::new("C:\\Temp").expect("dir"),
        ));
        assert_eq!(
            through(&mut ready(now), false, &directory, CHUNK, now).expect("dropped"),
            None
        );
        assert!(through(&mut ready(now), true, &directory, CHUNK, now).is_err());
        let contents = pdu(&ClipboardPdu::FileContentsRequest(FileContentsRequest {
            stream_id: 1,
            index: 0,
            flags: FileContentsFlags::SIZE,
            position: 0,
            requested_size: 8,
            data_id: None,
        }));
        let lock = pdu(&ClipboardPdu::LockData(LockDataId(1)));
        let unlock = pdu(&ClipboardPdu::UnlockData(LockDataId(1)));
        let ready_pdu = pdu(&ClipboardPdu::MonitorReady);
        for (message, from_server) in [
            (&contents, true),
            (&contents, false),
            (&lock, false),
            (&unlock, true),
            (&ready_pdu, false),
        ] {
            assert!(through(&mut ready(now), from_server, message, CHUNK, now).is_err());
        }
        assert!(through(&mut ready(now), true, &ready_pdu, CHUNK, now).is_ok());
        let answer = pdu(&ClipboardPdu::FormatListResponse(FormatListResponse::Ok));
        assert!(through(&mut ready(now), false, &answer, CHUNK, now).is_ok());
    }

    /// Windows' clipboard may never open: rdpclip can stop answering a
    /// session. What IronRDP sends with each paste before it does is checked
    /// and dropped, and the session goes on. Once Windows' clipboard opens,
    /// the same messages pass.
    #[test]
    fn the_browser_waits_for_windows_clipboard_to_open() {
        let now = Instant::now();
        let all = ClipboardGeneralCapabilityFlags::all();
        let directory = pdu(&ClipboardPdu::TemporaryDirectory(
            ClientTemporaryDirectory::new("C:\\Temp").expect("dir"),
        ));
        let text = [ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)];
        let paste = [caps(all), directory.clone(), list(&text, true)];
        let mut clip = Clipboard::default();
        // IronRDP's first paste and its second: dropped, nothing recorded.
        for _ in 0..2 {
            for message in &paste {
                assert_eq!(through(&mut clip, false, message, CHUNK, now).expect("dropped"), None);
            }
        }
        // Still checked: malformed capabilities, a list with other flags, and
        // any other message.
        let mut bad_caps = caps(all);
        bad_caps[16] = 3;
        let mut flagged = list(&text, true);
        flagged[2] = 0x01;
        let answer = pdu(&ClipboardPdu::FormatListResponse(FormatListResponse::Ok));
        for message in [&bad_caps, &flagged, &request(), &answer] {
            assert!(through(&mut Clipboard::default(), false, message, CHUNK, now).is_err());
        }
        // Windows' capabilities alone do not open it; its Monitor Ready does.
        through(&mut clip, true, &caps(all), CHUNK, now)
            .expect("server caps")
            .expect("passed");
        assert_eq!(
            through(&mut clip, false, &list(&text, true), CHUNK, now).expect("dropped"),
            None
        );
        through(&mut clip, true, &pdu(&ClipboardPdu::MonitorReady), CHUNK, now)
            .expect("ready")
            .expect("passed");
        // IronRDP then says it all again, and it passes.
        let out = through(&mut clip, false, &caps(all), CHUNK, now)
            .expect("caps")
            .expect("passed");
        let ClipboardPdu::Capabilities(passed) = decode::<ClipboardPdu<'_>>(&out).expect("decodes") else {
            panic!("not capabilities");
        };
        assert_eq!(passed.flags(), ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES);
        assert_eq!(
            through(&mut clip, false, &directory, CHUNK, now).expect("dropped"),
            None
        );
        let out = through(&mut clip, false, &list(&text, true), CHUNK, now)
            .expect("list")
            .expect("passed");
        assert_eq!(formats_of(&out, true), vec![13]);
        // Its capabilities still come once.
        assert!(through(&mut clip, false, &caps(all), CHUNK, now).is_err());
    }

    #[test]
    fn chunks_must_come_whole_and_in_order() {
        let now = Instant::now();
        let message = list(&rich(), true);
        let chunk = |total: usize, flags: u32, part: &[u8]| {
            let mut c = u32::try_from(total).expect("small").to_le_bytes().to_vec();
            c.extend_from_slice(&flags.to_le_bytes());
            c.extend_from_slice(part);
            c
        };
        let (a, b) = message.split_at(10);
        let n = message.len();
        for steps in [
            vec![chunk(n, LAST, b)],                                     // a later chunk first
            vec![chunk(n, FIRST, a), chunk(n, FIRST | LAST, b)],         // a first chunk inside a message
            vec![chunk(n, FIRST, a), chunk(n + 1, LAST, b)],             // the total changes
            vec![chunk(n, FIRST | LAST, a)],                             // last too early
            vec![chunk(n, FIRST, &message)],                             // whole, but not marked last
            vec![chunk(n, FIRST | 0x0020_0000, a)],                      // compressed
            vec![chunk(n, FIRST | SHOW_PROTOCOL, a), chunk(n, LAST, b)], // show-protocol changes
            vec![chunk(n, FIRST, &[])],                                  // empty
            vec![chunk(4, FIRST | LAST, &message[..4])],                 // shorter than a header
        ] {
            let mut clip = ready(now);
            let result = steps
                .iter()
                .try_for_each(|c| clip.chunk(true, IO, CLIP, c, now).map(|_| ()));
            assert!(result.is_err(), "{steps:?}");
        }
    }

    #[test]
    fn transfers_are_paced_as_the_gateway_paces_them() {
        let start = Instant::now();
        let mut clip = ready(start);
        through(&mut clip, true, &list(&rich(), true), CHUNK, start).expect("list");
        let mut send = |at: Instant| {
            through(&mut clip, false, &request(), CHUNK, at).expect("request");
            let out = through(&mut clip, true, &response(utf16("x")), CHUNK, at)
                .expect("response")
                .expect("passed");
            text_of(&out).is_some()
        };
        assert!((0..128).all(|_| send(start)), "the burst passes");
        assert!(!send(start), "beyond the burst, a failure");
        assert!(send(start + Duration::from_secs(1)), "one more a second later");
        assert!(!send(start + Duration::from_secs(1)));
    }

    #[test]
    fn requests_waiting_are_bounded() {
        let now = Instant::now();
        let mut clip = ready(now);
        for _ in 0..MAX_PENDING {
            through(&mut clip, true, &request(), CHUNK, now).expect("request");
        }
        assert!(through(&mut clip, true, &request(), CHUNK, now).is_err());
    }
}
