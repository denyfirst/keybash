//! Randomised tests of every parser the proxy runs on bytes it does not
//! control (ADR 0008, step 2: fuzzed parsers). Each target is fed mutations
//! of real messages, from a valid prefix so the deeper states are reached,
//! and plain noise. The seeds are fixed, so a failure repeats. For each
//! target: no panic (release builds treat integer overflow as a panic too),
//! and whatever passes stays within its bounds.
//!
//! `KEYBASH_FUZZ_ROUNDS` runs longer than the default.

use std::borrow::Cow;
use std::time::Instant;

use ironrdp_core::{decode, encode_vec};
use ironrdp_pdu::x224::{X224, X224Data};
use ironrdp_pdu::{Action, mcs, nego};

use crate::channels::{Channels, MAX_PDU, Pass, Splitter};
use crate::clipboard::{Clipboard, MAX_TEXT};

/// xorshift64*: small, fixed seeds, the same run every time.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        let n = u64::try_from(n.max(1)).expect("small");
        usize::try_from(self.next() % n).expect("small")
    }

    fn byte(&mut self) -> u8 {
        self.next().to_le_bytes()[0]
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

fn rounds() -> usize {
    std::env::var("KEYBASH_FUZZ_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3_000)
}

/// A mutation of `seed`: bits flipped, bytes set to edge values, inserted,
/// removed, cut short, or a length-like field changed.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut out = seed.to_vec();
    for _ in 0..=rng.below(3) {
        let len = out.len();
        match rng.below(7) {
            0 if len > 0 => {
                let i = rng.below(len);
                out[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                out[i] = [0, 1, 0x7F, 0x80, 0xFF][rng.below(5)];
            }
            2 => {
                let i = rng.below(len + 1);
                out.insert(i, rng.byte());
            }
            3 if len > 0 => {
                let i = rng.below(len);
                out.remove(i);
            }
            4 => {
                let keep = rng.below(len + 1);
                out.truncate(keep);
            }
            5 if len >= 4 => {
                let i = rng.below(len - 3);
                let wide = u32::try_from(len).unwrap_or(u32::MAX);
                let v = [0, 1, 0xFFFF, 0xFFFF_FFFF, wide, wide.saturating_add(1)][rng.below(6)];
                out[i..i + 4].copy_from_slice(&v.to_le_bytes());
            }
            6 if len >= 2 => {
                let i = rng.below(len - 1);
                let narrow = u16::try_from(len).unwrap_or(u16::MAX);
                let v = [0, 1, 7, 0xFFFF, narrow, narrow.saturating_add(1)][rng.below(6)];
                out[i..i + 2].copy_from_slice(&v.to_be_bytes());
            }
            _ => {}
        }
    }
    out
}

fn noise(rng: &mut Rng, most: usize) -> Vec<u8> {
    (0..rng.below(most)).map(|_| rng.byte()).collect()
}

const IO: u16 = 1003;
const USER: u16 = 1002;
const DRDYNVC: u16 = 1004;
const CLIPRDR: u16 = 1005;

fn send_data(from_server: bool, channel_id: u16, data: Vec<u8>) -> Vec<u8> {
    let user_data = Cow::Owned(data);
    let message = if from_server {
        mcs::McsMessage::SendDataIndication(mcs::SendDataIndication {
            initiator_id: USER,
            channel_id,
            user_data,
        })
    } else {
        mcs::McsMessage::SendDataRequest(mcs::SendDataRequest {
            initiator_id: USER,
            channel_id,
            user_data,
        })
    };
    encode_vec(&X224(message)).expect("mcs")
}

/// One whole channel message in a single chunk.
fn chunk(message: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(message.len()).expect("small").to_le_bytes().to_vec();
    out.extend_from_slice(&0x13u32.to_le_bytes()); // first, last, show protocol
    out.extend_from_slice(message);
    out
}

/// A channel message as it goes in its PDU: chunked on static channels, as
/// it is on the I/O channel.
fn wrap(channel: u16, message: &[u8]) -> Vec<u8> {
    if channel == IO {
        message.to_vec()
    } else {
        chunk(message)
    }
}

/// A browser's Client Info, with someone else's name, a password and both
/// cookies, which the proxy writes again.
fn client_info_seed() -> Vec<u8> {
    use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
    crate::channels::tests::client_info("", "", ClientInfoFlags::MOUSE | ClientInfoFlags::UNICODE, true)
}

fn connect_response() -> Vec<u8> {
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
            channel_ids: vec![DRDYNVC, CLIPRDR],
            io_channel: IO,
        },
        security: ServerSecurityData::no_security(),
        message_channel: None,
        multi_transport_channel: None,
    };
    let response = mcs::ConnectResponse {
        conference_create_response: ConferenceCreateResponse::new(USER, blocks).expect("blocks"),
        called_connect_id: 1,
        domain_parameters: mcs::DomainParameters::target(),
    };
    let body = encode_vec(&response).expect("response");
    encode_vec(&X224(X224Data { data: Cow::Owned(body) })).expect("x224")
}

fn utf16z(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

fn clip(kind: u16, flags: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_le_bytes().to_vec();
    out.extend_from_slice(&flags.to_le_bytes());
    out.extend_from_slice(&u32::try_from(body.len()).expect("small").to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn clip_caps() -> Vec<u8> {
    let mut body = vec![1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0];
    body.extend_from_slice(&0x3Eu32.to_le_bytes());
    clip(7, 0, &body)
}

fn clip_list() -> Vec<u8> {
    let mut body = Vec::new();
    for (id, name) in [
        (13u32, ""),
        (1, ""),
        (0xC0F1, "HTML Format"),
        (0xC0F2, "FileGroupDescriptorW"),
    ] {
        body.extend_from_slice(&id.to_le_bytes());
        body.extend_from_slice(&utf16z(name));
    }
    clip(2, 0, &body)
}

fn display_layout(width: u32, height: u32, scale: u32) -> Vec<u8> {
    let mut out = vec![0x30, 7];
    for word in [2, 56, 40, 1, 1, 0, 0, width, height, 0, 0, 0, scale, 100] {
        out.extend_from_slice(&u32::to_le_bytes(word));
    }
    out
}

/// Messages a desktop really carries, each way, for the channels the proxy
/// checks: (from Windows, channel, payload before chunking).
fn corpus() -> Vec<(bool, u16, Vec<u8>)> {
    let graphics = b"Microsoft::Windows::RDS::Graphics\0";
    let display = b"Microsoft::Windows::RDS::DisplayControl\0";
    let mut create_graphics = vec![0x10, 3];
    create_graphics.extend_from_slice(graphics);
    let mut create_display = vec![0x10, 7];
    create_display.extend_from_slice(display);
    let mut create_other = vec![0x10, 9];
    create_other.extend_from_slice(b"rdpdr_dvc\0");
    vec![
        (false, IO, client_info_seed()),
        (true, DRDYNVC, vec![0x50, 0x00, 0x03, 0x00]),
        (false, DRDYNVC, vec![0x50, 0x00, 0x03, 0x00]),
        (true, DRDYNVC, create_graphics),
        (false, DRDYNVC, vec![0x10, 3, 0, 0, 0, 0]),
        (true, DRDYNVC, create_display),
        (false, DRDYNVC, vec![0x10, 7, 0, 0, 0, 0]),
        (true, DRDYNVC, create_other),
        (false, DRDYNVC, vec![0x10, 9, 0xFF, 0xFF, 0xFF, 0xFF]),
        (true, DRDYNVC, vec![0x30, 3, 1, 2, 3, 4, 5, 6, 7, 8]),
        (false, DRDYNVC, vec![0x30, 3, 1, 2]),
        (false, DRDYNVC, display_layout(1280, 720, 100)),
        (true, DRDYNVC, vec![0x40, 9]),
        (true, CLIPRDR, clip_caps()),
        (true, CLIPRDR, clip(1, 0, &[])),
        (false, CLIPRDR, clip_caps()),
        (false, CLIPRDR, clip_list()),
        (true, CLIPRDR, clip(3, 1, &[])),
        (true, CLIPRDR, clip_list()),
        (false, CLIPRDR, clip(3, 1, &[])),
        (false, CLIPRDR, clip(4, 0, &13u32.to_le_bytes())),
        (true, CLIPRDR, clip(5, 1, &utf16z("héllo 🙂"))),
        (true, CLIPRDR, clip(4, 0, &13u32.to_le_bytes())),
        (false, CLIPRDR, clip(5, 1, &utf16z("back"))),
        (false, CLIPRDR, clip(6, 0, &[0; 520])),
    ]
}

/// What the proxy passes on in place of a PDU must itself be whole MCS PDUs
/// whose clipboard chunks are bounded.
fn check_instead(pdus: &[Vec<u8>]) {
    for pdu in pdus {
        assert!(pdu.len() <= MAX_PDU, "a PDU over the limit passed");
        let X224(message) = decode::<X224<mcs::McsMessage<'_>>>(pdu).expect("what passes decodes");
        let (channel, data) = match message {
            mcs::McsMessage::SendDataIndication(d) => (d.channel_id, d.user_data),
            mcs::McsMessage::SendDataRequest(d) => (d.channel_id, d.user_data),
            _ => panic!("only channel data is written again"),
        };
        if channel == IO {
            // The Client Info, written again for the account, with no password.
            let info = decode::<ironrdp_pdu::rdp::ClientInfoPdu>(&data).expect("a Client Info");
            assert_eq!(info.client_info.credentials.username, "kb-user");
            assert!(info.client_info.credentials.password.is_empty());
            assert!(info.client_info.password_cookie.is_none());
            continue;
        }
        assert!(data.len() <= 8 + 1600, "a chunk over 1600 bytes");
        let total = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert!(
            usize::try_from(total).expect("small") <= 8 + 2 * MAX_TEXT + 2,
            "a message over the limit"
        );
    }
}

/// Windows and the browser in turn: a valid start, then mutated messages,
/// until the proxy ends the session or the sequence is spent.
#[test]
fn channel_checks_survive_mutated_desktops() {
    let mut rng = Rng(0x6B65_7962_6173_6801);
    let corpus = corpus();
    let (mut passed, mut refused) = (0usize, 0usize);
    for _ in 0..rounds() {
        let mut c = Channels::new(vec!["drdynvc".into(), "cliprdr".into()], true).for_account("kb-user", "KB");
        assert_eq!(c.server_pdu(Action::X224, &connect_response()), Ok(Pass::Unchanged));
        let attach = encode_vec(&X224(mcs::McsMessage::AttachUserConfirm(mcs::AttachUserConfirm {
            result: 0,
            initiator_id: USER,
        })))
        .expect("attach");
        assert_eq!(c.server_pdu(Action::X224, &attach), Ok(Pass::Unchanged));
        // A valid prefix of random length, then mutations.
        let prefix = rng.below(corpus.len() + 1);
        for (from_server, channel, payload) in &corpus[..prefix] {
            let pdu = send_data(*from_server, *channel, wrap(*channel, payload));
            let pass = if *from_server {
                c.server_pdu(Action::X224, &pdu)
            } else {
                c.browser_pdu(Action::X224, &pdu)
            };
            assert!(pass.is_ok(), "the valid desktop was refused");
        }
        for _ in 0..8 {
            let (from_server, channel, payload) = &corpus[rng.below(corpus.len())];
            let from_server = if rng.chance(8) { !from_server } else { *from_server };
            let pdu = match rng.below(4) {
                // Inside the channel message, so the deeper parsers see it.
                0 | 1 => send_data(from_server, *channel, wrap(*channel, &mutate(&mut rng, payload))),
                // The chunk header and the message.
                2 => send_data(from_server, *channel, mutate(&mut rng, &wrap(*channel, payload))),
                // The whole PDU.
                _ => mutate(&mut rng, &send_data(from_server, *channel, wrap(*channel, payload))),
            };
            let action = if rng.chance(16) { Action::FastPath } else { Action::X224 };
            let result = if from_server {
                c.server_pdu(action, &pdu)
            } else {
                c.browser_pdu(action, &pdu)
            };
            match result {
                Ok(Pass::Instead(pdus)) => {
                    check_instead(&pdus);
                    passed += 1;
                }
                Ok(Pass::Unchanged) => passed += 1,
                Err(_) => {
                    refused += 1;
                    break;
                }
            }
        }
    }
    assert!(passed > 0 && refused > 0, "{passed} passed, {refused} refused");
}

/// The clipboard alone, with messages split into chunks at random, both
/// sides interleaved.
#[test]
fn the_clipboard_survives_mutated_messages() {
    let mut rng = Rng(0x6B65_7962_6173_6802);
    let messages: Vec<(bool, Vec<u8>)> = corpus()
        .into_iter()
        .filter(|(_, channel, _)| *channel == CLIPRDR)
        .map(|(from_server, _, payload)| (from_server, payload))
        .collect();
    let now = Instant::now();
    for _ in 0..rounds() {
        let mut clipboard = Clipboard::default();
        for _ in 0..12 {
            let (from_server, message) = &messages[rng.below(messages.len())];
            let message = if rng.chance(2) {
                mutate(&mut rng, message)
            } else {
                message.clone()
            };
            let size = 1 + rng.below(message.len().max(1));
            let parts: Vec<&[u8]> = message.chunks(size).collect();
            let mut ended = false;
            for (i, part) in parts.iter().enumerate() {
                let mut flags = 0x10u32;
                if i == 0 {
                    flags |= 1;
                }
                if i + 1 == parts.len() {
                    flags |= 2;
                }
                let mut data = u32::try_from(message.len()).expect("small").to_le_bytes().to_vec();
                data.extend_from_slice(&flags.to_le_bytes());
                data.extend_from_slice(part);
                if rng.chance(20) {
                    data = mutate(&mut rng, &data);
                }
                match clipboard.chunk(*from_server, USER, CLIPRDR, &data, now) {
                    Ok(pdus) => check_instead(&pdus),
                    Err(_) => {
                        ended = true;
                        break;
                    }
                }
            }
            if ended {
                break;
            }
        }
    }
}

/// The first PDU the proxy rebuilds: whatever passes asks only for allowed
/// channels, each once, and fits the limit.
#[test]
fn the_connect_initial_check_survives_mutations() {
    let mut rng = Rng(0x6B65_7962_6173_6803);
    let seeds = [
        crate::policy::tests::browser_connect_initial(1600, 900, 100),
        crate::policy::tests::browser_connect_initial(1280, 720, 200),
    ];
    let mut passed = 0usize;
    for _ in 0..rounds() {
        let input = if rng.chance(10) {
            noise(&mut rng, 600)
        } else {
            let seed = &seeds[rng.below(seeds.len())];
            mutate(&mut rng, seed)
        };
        let clipboard = rng.chance(2);
        let selected = [
            nego::SecurityProtocol::HYBRID,
            nego::SecurityProtocol::HYBRID_EX,
            nego::SecurityProtocol::SSL,
        ][rng.below(3)];
        if let Ok((pdu, names)) = crate::policy::connect_initial(&input, selected, clipboard) {
            passed += 1;
            assert!(pdu.len() <= crate::policy::MAX_CONNECT_INITIAL);
            let unique: std::collections::HashSet<&String> = names.iter().collect();
            assert_eq!(unique.len(), names.len(), "a channel twice");
            assert!(
                names.iter().all(|n| n == "drdynvc" || (clipboard && n == "cliprdr")),
                "{names:?}"
            );
        }
    }
    assert!(passed > 0, "no mutation passed; the corpus is not reaching the checks");
}

/// The splitter on streams of real and broken PDUs, cut anywhere.
#[test]
fn the_splitter_survives_broken_streams() {
    let mut rng = Rng(0x6B65_7962_6173_6804);
    let seeds: Vec<Vec<u8>> = corpus()
        .into_iter()
        .map(|(from_server, channel, payload)| send_data(from_server, channel, wrap(channel, &payload)))
        .chain([vec![0x00, 0x05, 1, 2, 3], vec![0x00, 0x82, 0x00, 1, 2, 3]])
        .collect();
    for _ in 0..rounds() {
        let mut stream = Vec::new();
        for _ in 0..1 + rng.below(6) {
            let seed = &seeds[rng.below(seeds.len())];
            stream.extend(if rng.chance(4) {
                mutate(&mut rng, seed)
            } else {
                seed.clone()
            });
        }
        let mut splitter = Splitter::default();
        let mut rest = &stream[..];
        while !rest.is_empty() {
            let (piece, after) = rest.split_at(1 + rng.below(rest.len()));
            rest = after;
            match splitter.push(piece) {
                Ok(pdus) => {
                    for (action, pdu) in pdus {
                        let least = if action == Action::X224 { 7 } else { 2 };
                        assert!((least..=MAX_PDU).contains(&pdu.len()));
                    }
                }
                Err(_) => break,
            }
        }
    }
}

/// The setup frame, the pipe frames and the trust files.
#[test]
fn setup_frames_and_trust_files_survive_mutations() {
    let mut rng = Rng(0x6B65_7962_6173_6805);
    let setup = crate::setup::encode("kb-user", "KB", "kb-password", true);
    let frame = {
        let mut f = vec![2u8];
        f.extend_from_slice(&5u32.to_le_bytes());
        f.extend_from_slice(b"hello");
        f
    };
    let der = crate::pin::tests::certificate_der();
    let runtime = tokio::runtime::Builder::new_current_thread().build().expect("runtime");
    for _ in 0..rounds() {
        let input = mutate(&mut rng, &setup);
        if let Ok(parsed) = crate::setup::parse(&input) {
            assert!(!parsed.user.is_empty() && !parsed.password.as_str().is_empty());
        }
        let input = if rng.chance(4) {
            noise(&mut rng, 64)
        } else {
            mutate(&mut rng, &frame)
        };
        if let Ok((_, payload)) = runtime.block_on(crate::frame::read(&mut &input[..])) {
            assert!(payload.len() <= crate::frame::MAX_PAYLOAD);
        }
        let _ = crate::pin::name(&noise(&mut rng, 80));
        let _ = crate::pin::public_key(&mutate(&mut rng, &der));
    }
}
