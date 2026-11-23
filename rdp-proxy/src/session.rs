//! One desktop: the browser's RDCleanPath request, X.224, TLS and NLA with
//! Windows, the checked Connect Initial, then the relay.

use std::net::SocketAddr;

use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{ClientConnector, ConnectorResult, Credentials, Sequence as _, ServerName};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage};
use ironrdp_pdu::nego;
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPathMessage, RDCleanPathPdu};
use ironrdp_tokio::FramedWrite as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

use std::cell::{Cell, RefCell};

use crate::channels::{Channels, Pass, Splitter};
use crate::frame::{self, Ended, FrameError, Kind};
use crate::policy;
use crate::refusal::{Refusal, Side};
use crate::setup::Setup;

/// The browser's RDCleanPath request is small; anything larger is refused.
const MAX_REQUEST: usize = 16 * 1024;

/// The pinned certificate (DER) and the name Windows is known by.
#[derive(Clone)]
pub struct Trust {
    pub certificate: Vec<u8>,
    pub name: crate::pin::Name,
}

/// How a session ended: with a word for the gateway, refused (the side that
/// sent what the proxy does not accept, and what), or quietly because the
/// gateway or the browser went away.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    End(Ended),
    Refused(Side, Refusal),
    Quiet,
}

impl Fail {
    fn browser(refusal: Refusal) -> Self {
        Fail::Refused(Side::Browser, refusal)
    }

    fn windows(refusal: Refusal) -> Self {
        Fail::Refused(Side::Windows, refusal)
    }

    pub fn keybash(refusal: Refusal) -> Self {
        Fail::Refused(Side::Keybash, refusal)
    }

    /// The Ended frame's payload, when the gateway is to hear why: the end's
    /// code, or for a refusal `frame::REFUSED`, the side and the refusal.
    /// Fixed codes only: nothing that came from either side.
    pub fn ended(&self) -> Option<Vec<u8>> {
        match self {
            Fail::End(end) => Some(vec![*end as u8]),
            Fail::Refused(side, refusal) => Some(vec![frame::REFUSED, *side as u8, *refusal as u8]),
            Fail::Quiet => None,
        }
    }
}

impl From<FrameError> for Fail {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Closed => Fail::Quiet,
            FrameError::Malformed => Fail::keybash(Refusal::GatewayFrame),
        }
    }
}

/// Appends the next browser message; anything but a browser frame ends it,
/// and so does a total past `most`, as `too_large`.
async fn browser_bytes<R: AsyncRead + Unpin>(
    gateway: &mut R,
    into: &mut Vec<u8>,
    most: usize,
    too_large: Refusal,
) -> Result<(), Fail> {
    let (kind, payload) = frame::read(gateway).await?;
    if kind != Kind::Browser {
        return Err(Fail::keybash(Refusal::GatewayFrame));
    }
    if into.len() + payload.len() > most {
        return Err(Fail::browser(too_large));
    }
    into.extend_from_slice(&payload);
    Ok(())
}

/// Reads the browser's RDCleanPath request and returns its X.224 request.
async fn rdcleanpath_request<R: AsyncRead + Unpin>(gateway: &mut R, inbuf: &mut Vec<u8>) -> Result<Vec<u8>, Fail> {
    let request = loop {
        match RDCleanPathPdu::detect(inbuf) {
            DetectionResult::Detected { total_length, .. } if total_length > MAX_REQUEST => {
                return Err(Fail::browser(Refusal::RdcleanpathTooLarge));
            }
            DetectionResult::Detected { total_length, .. } if inbuf.len() >= total_length => {
                break inbuf.drain(..total_length).collect::<Vec<u8>>();
            }
            DetectionResult::Detected { .. } | DetectionResult::NotEnoughBytes => {}
            DetectionResult::Failed => return Err(Fail::browser(Refusal::RdcleanpathRequest)),
        }
        browser_bytes(gateway, inbuf, MAX_REQUEST, Refusal::RdcleanpathTooLarge).await?;
    };
    let message = RDCleanPathPdu::from_der(&request)
        .map_err(|_| Fail::browser(Refusal::RdcleanpathRequest))?
        .into_message()
        .map_err(|_| Fail::browser(Refusal::RdcleanpathRequest))?;
    // The destination and the token are not used: the target and the access
    // are the gateway's. Anything that would change the connection is refused.
    let RDCleanPathMessage::Request {
        preconnection_blob,
        server_auth,
        x224_connection_request,
        ..
    } = message
    else {
        return Err(Fail::browser(Refusal::RdcleanpathRequest));
    };
    if preconnection_blob.is_some() || server_auth.is_some() {
        return Err(Fail::browser(Refusal::ConnectionChange));
    }
    let x224 = x224_connection_request.as_bytes().to_vec();
    let X224(request) =
        decode::<X224<nego::ConnectionRequest>>(&x224).map_err(|_| Fail::browser(Refusal::X224Request))?;
    if request.protocol != nego::SecurityProtocol::SSL {
        return Err(Fail::browser(Refusal::SecurityNotTls));
    }
    Ok(x224)
}

fn windows_config(setup: &Setup) -> ironrdp_connector::Config {
    let domain = (!setup.domain.is_empty()).then(|| setup.domain.clone());
    let mut config = crate::config::connector_config();
    config.credentials = Credentials::UsernamePassword {
        username: setup.user.clone(),
        password: setup.password.as_str().to_owned(),
    };
    config.domain = domain;
    config
}

/// NTLM only: the sandbox has no route to a KDC, so no request is made.
struct NoNetwork;

impl ironrdp_tokio::NetworkClient for NoNetwork {
    async fn send(&mut self, _request: &NetworkRequest) -> ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::general_err!("no network requests from the proxy"))
    }
}

/// Runs one session to its end. `target` is the bridge to Windows.
pub async fn run<R, W>(gateway_in: &mut R, gateway_out: &mut W, setup: Setup, trust: &Trust, target: SocketAddr) -> Fail
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Everything up to the checked Connect Initial has a deadline: a browser,
    // or a server, that stalls the handshake cannot hold a worker.
    // The side the handshake waits on, for a handshake that runs out of time.
    let clipboard = setup.clipboard;
    let (user, domain) = (setup.user.clone(), setup.domain.clone());
    let waiting = Cell::new(Side::Browser);
    let handshake = tokio::time::timeout(
        HANDSHAKE_WAIT,
        handshake(gateway_in, gateway_out, setup, trust, target, &waiting),
    );
    let (tls, checked, names, rest) = match handshake.await {
        Ok(Ok(ready)) => ready,
        Ok(Err(fail)) => return fail,
        Err(_) => return Fail::Refused(waiting.get(), Refusal::HandshakeTooSlow),
    };
    let (mut from_windows, mut to_windows) = tokio::io::split(tls);
    if to_windows.write_all(&checked).await.is_err() {
        return Fail::End(Ended::Remote);
    }
    let channels = RefCell::new(Channels::new(names, clipboard).for_account(&user, &domain));
    relay(
        gateway_in,
        gateway_out,
        &mut from_windows,
        &mut to_windows,
        &channels,
        &rest,
    )
    .await
}

/// The relay: whole PDUs each way, each checked against the channels before
/// it passes (crate::channels). Both directions run in this one task, so they
/// share the state without locks. When it ends on Keybash's side, Windows is
/// told so (`goodbye`).
async fn relay<GR, GW, WR, WW>(
    gateway_in: &mut GR,
    gateway_out: &mut GW,
    from_windows: &mut WR,
    to_windows: &mut WW,
    channels: &RefCell<Channels>,
    rest: &[u8],
) -> Fail
where
    GR: AsyncRead + Unpin,
    GW: AsyncWrite + Unpin,
    WR: AsyncRead + Unpin,
    WW: AsyncWrite + Unpin,
{
    let writing = Cell::new(false);
    let mut browser = Splitter::default();
    let fail = match pass_browser_bytes(rest, &mut browser, channels, to_windows, &writing).await {
        Err(fail) => fail,
        Ok(()) => tokio::select! {
            fail = upstream(gateway_in, to_windows, &mut browser, channels, &writing) => fail,
            fail = downstream(from_windows, gateway_out, channels) => fail,
        },
    };
    // Nothing more can be said when Windows ended it, or when a write to
    // Windows was cut part way through a PDU.
    if fail != Fail::End(Ended::Remote) && !writing.get() {
        goodbye(to_windows).await;
    }
    fail
}

/// How long telling Windows that the session is over may take, at most.
const GOODBYE_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// Tells Windows the session is over, as a client ends one: the MCS Disconnect
/// Provider Ultimatum (user requested), then TLS's close. A connection that
/// just vanishes leaves Windows holding the session's graphics for a while, and
/// a desktop opened again at once got no picture. Best effort and bounded.
async fn goodbye<W: AsyncWrite + Unpin>(windows: &mut W) {
    let ultimatum = McsMessage::DisconnectProviderUltimatum(DisconnectProviderUltimatum::from_reason(
        DisconnectReason::UserRequested,
    ));
    let Ok(pdu) = encode_vec(&X224(ultimatum)) else {
        return;
    };
    let _ = tokio::time::timeout(GOODBYE_WAIT, async {
        windows.write_all(&pdu).await?;
        windows.flush().await?;
        windows.shutdown().await
    })
    .await;
}

/// Splits browser bytes into PDUs, checks each, and sends the ones that pass.
/// `writing` is true while bytes are on their way to Windows.
async fn pass_browser_bytes<W: AsyncWrite + Unpin>(
    bytes: &[u8],
    splitter: &mut Splitter,
    channels: &RefCell<Channels>,
    windows: &mut W,
    writing: &Cell<bool>,
) -> Result<(), Fail> {
    let pdus = splitter.push(bytes).map_err(Fail::browser)?;
    let mut out = Vec::new();
    for (action, pdu) in &pdus {
        match channels.borrow_mut().browser_pdu(*action, pdu).map_err(Fail::browser)? {
            Pass::Unchanged => out.extend_from_slice(pdu),
            Pass::Instead(instead) => instead.iter().for_each(|p| out.extend_from_slice(p)),
        }
    }
    writing.set(true);
    windows.write_all(&out).await.map_err(|_| Fail::End(Ended::Remote))?;
    windows.flush().await.map_err(|_| Fail::End(Ended::Remote))?;
    writing.set(false);
    Ok(())
}

/// The handshake must finish within this long, from the browser's first byte.
#[cfg(not(test))]
const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const HANDSHAKE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

type Ready = (
    tokio_rustls::client::TlsStream<TcpStream>,
    Vec<u8>,
    Vec<String>,
    Vec<u8>,
);

/// Returns TLS with Windows after NLA, the checked Connect Initial, the static
/// channel names it asks for, and any browser bytes that came after it.
/// `waiting` names the side each step waits on.
async fn handshake<R, W>(
    gateway_in: &mut R,
    gateway_out: &mut W,
    setup: Setup,
    trust: &Trust,
    target: SocketAddr,
    waiting: &Cell<Side>,
) -> Result<Ready, Fail>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let internal = || Fail::keybash(Refusal::Internal);
    let clipboard = setup.clipboard;
    let mut inbuf = Vec::new();
    waiting.set(Side::Browser);
    rdcleanpath_request(gateway_in, &mut inbuf).await?;

    // Windows: X.224 asking for NLA, TLS against the pinned certificate, then
    // CredSSP with the credentials only this process holds.
    waiting.set(Side::Windows);
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    tcp.set_nodelay(true).map_err(|_| Fail::End(Ended::Unreachable))?;
    // Nothing about the account crosses the network before TLS. IronRDP puts
    // the user name in the X.224 request as a routing cookie, so the request
    // is made by a connector that has no user name; the connector with the
    // credentials then follows the same confirmation, and its own request is
    // never sent.
    let local = "127.0.0.1:0".parse().map_err(|_| internal())?;
    let mut nameless = ClientConnector::new(crate::config::connector_config(), local);
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut buf = WriteBuf::new();
    nameless.step_no_input(&mut buf).map_err(|_| internal())?;
    framed
        .write_all(buf.filled())
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    let hint = nameless.next_pdu_hint().ok_or_else(internal)?;
    let confirm = framed
        .read_by_hint(hint)
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    let mut connector = ClientConnector::new(windows_config(&setup), local);
    let mut unsent = WriteBuf::new();
    connector.step_no_input(&mut unsent).map_err(|_| internal())?;
    drop(unsent);
    buf.clear();
    // Windows' answer is read before the connector takes it, so an answer
    // without NLA (TLS alone, standard RDP security, or a negotiation failure)
    // is named so; only bytes that are no answer at all are the confirm's.
    let X224(answer) =
        decode::<X224<nego::ConnectionConfirm>>(&confirm).map_err(|_| Fail::windows(Refusal::X224Confirm))?;
    let nego::ConnectionConfirm::Response {
        flags,
        protocol: selected,
    } = answer
    else {
        return Err(Fail::windows(Refusal::NlaNotSelected));
    };
    if !selected.intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX) {
        return Err(Fail::windows(Refusal::NlaNotSelected));
    }
    connector
        .step(&confirm, None, &mut buf)
        .map_err(|_| Fail::windows(Refusal::X224Confirm))?;
    if !connector.should_perform_security_upgrade() {
        return Err(Fail::windows(Refusal::NlaNotSelected));
    }
    let (tcp, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(Fail::windows(Refusal::BytesBeforeTls));
    }
    let tls = crate::pin::connect(tcp, &trust.certificate, &trust.name)
        .await
        .map_err(|_| Fail::windows(Refusal::Certificate))?;
    // The verifier accepted only the pinned bytes; the leaf is compared again,
    // as sent, before any credential leaves this process.
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or_else(|| Fail::windows(Refusal::Certificate))?
        .to_vec();
    if leaf != trust.certificate {
        return Err(Fail::windows(Refusal::Certificate));
    }
    let server_public_key =
        crate::pin::public_key(&trust.certificate).map_err(|_| Fail::keybash(Refusal::TrustFiles))?;
    connector.mark_security_upgrade_as_done();
    if !connector.should_perform_credssp() {
        return Err(internal());
    }
    let mut framed = ironrdp_tokio::TokioFramed::new(tls);
    let (sequence, ts_request) =
        CredsspSequence::init_for_connector(&connector, ServerName::from(trust.name.host()), server_public_key, None)
            .map_err(|_| internal())?;
    let sequence =
        ironrdp_tokio::perform_credssp_with_context(&mut framed, &mut NoNetwork, &mut buf, sequence, ts_request)
            .await
            .map_err(|_| Fail::End(Ended::Credentials))?;
    connector
        .complete_credssp(sequence)
        .map_err(|_| Fail::End(Ended::Credentials))?;
    drop(connector);
    drop(setup);
    let (tls, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(Fail::windows(Refusal::BytesAfterNla));
    }

    // The browser hears that TLS was selected, with the pinned certificate.
    let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
        flags,
        protocol: nego::SecurityProtocol::SSL,
    }))
    .map_err(|_| internal())?;
    let response = RDCleanPathPdu::new_response(trust.name.host().to_owned(), confirm, [trust.certificate.clone()])
        .and_then(|pdu| pdu.to_der())
        .map_err(|_| internal())?;
    waiting.set(Side::Browser);
    frame::write(gateway_out, Kind::Desktop, &response)
        .await
        .map_err(|_| Fail::Quiet)?;

    // The browser's Connect Initial, checked and re-encoded for Windows.
    let too_large = Refusal::ConnectInitialTooLarge;
    let total = loop {
        if inbuf.len() >= 4 {
            if inbuf[0] != 3 {
                return Err(Fail::browser(Refusal::ConnectInitial));
            }
            break usize::from(u16::from_be_bytes([inbuf[2], inbuf[3]]));
        }
        browser_bytes(gateway_in, &mut inbuf, policy::MAX_CONNECT_INITIAL, too_large).await?;
    };
    if !(7..=policy::MAX_CONNECT_INITIAL).contains(&total) {
        return Err(Fail::browser(Refusal::ConnectInitial));
    }
    while inbuf.len() < total {
        browser_bytes(gateway_in, &mut inbuf, policy::MAX_CONNECT_INITIAL, too_large).await?;
    }
    let first: Vec<u8> = inbuf.drain(..total).collect();
    let (checked, names) = policy::connect_initial(&first, selected, clipboard).map_err(Fail::browser)?;
    Ok((tls, checked, names, inbuf))
}

async fn upstream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    gateway: &mut R,
    windows: &mut W,
    splitter: &mut Splitter,
    channels: &RefCell<Channels>,
    writing: &Cell<bool>,
) -> Fail {
    loop {
        match frame::read(gateway).await {
            Ok((Kind::Browser, payload)) => {
                if let Err(fail) = pass_browser_bytes(&payload, splitter, channels, windows, writing).await {
                    return fail;
                }
            }
            Ok(_) => return Fail::keybash(Refusal::GatewayFrame),
            Err(e) => return e.into(),
        }
    }
}

async fn downstream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    windows: &mut R,
    gateway: &mut W,
    channels: &RefCell<Channels>,
) -> Fail {
    let mut chunk = vec![0u8; 32 * 1024];
    let mut splitter = Splitter::default();
    let mut out = Vec::new();
    loop {
        let n = match windows.read(&mut chunk).await {
            Ok(0) | Err(_) => return Fail::End(Ended::Remote),
            Ok(n) => n,
        };
        let pdus = match splitter.push(&chunk[..n]) {
            Ok(pdus) => pdus,
            Err(refusal) => return Fail::windows(refusal),
        };
        out.clear();
        for (action, pdu) in &pdus {
            match channels.borrow_mut().server_pdu(*action, pdu) {
                Ok(Pass::Unchanged) => out.extend_from_slice(pdu),
                Ok(Pass::Instead(instead)) => instead.iter().for_each(|p| out.extend_from_slice(p)),
                Err(refusal) => return Fail::windows(refusal),
            }
        }
        for part in out.chunks(frame::MAX_PAYLOAD) {
            if frame::write(gateway, Kind::Desktop, part).await.is_err() {
                return Fail::Quiet;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pin::Name;
    use tokio::io::duplex;

    fn run_async<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    /// The browser's first message: its X.224 request inside RDCleanPath.
    fn rdcleanpath_request_from_browser() -> (ClientConnector, Vec<u8>) {
        let mut connector = ClientConnector::new(
            crate::policy::tests::browser_config(1600, 900, 100),
            "127.0.0.1:0".parse().expect("addr"),
        );
        let mut buf = WriteBuf::new();
        connector.step_no_input(&mut buf).expect("X.224 request");
        let request = RDCleanPathPdu::new_request(buf.filled().to_vec(), "ignored".into(), "ignored".into(), None)
            .and_then(|pdu| pdu.to_der())
            .expect("request");
        (connector, request)
    }

    /// Plays the browser: IronRDP's connector told TLS only, then the whole
    /// connection sequence through the proxy.
    async fn browser(
        to_proxy: &mut tokio::io::DuplexStream,
        from_proxy: &mut tokio::io::DuplexStream,
    ) -> Result<(), String> {
        let (mut connector, request) = rdcleanpath_request_from_browser();
        frame::write(to_proxy, Kind::Browser, &request)
            .await
            .map_err(|e| e.to_string())?;
        let (kind, payload) = frame::read(from_proxy).await.map_err(|e| format!("response: {e:?}"))?;
        if kind != Kind::Desktop {
            return Err(format!("expected the RDCleanPath response, got {kind:?} {payload:?}"));
        }
        let Ok(RDCleanPathMessage::Response {
            x224_connection_response,
            server_cert_chain,
            ..
        }) = RDCleanPathPdu::from_der(&payload)
            .map_err(|_| ())
            .and_then(|pdu| pdu.into_message().map_err(|_| ()))
        else {
            return Err("not an RDCleanPath response".into());
        };
        let mut buf = WriteBuf::new();
        connector
            .step(x224_connection_response.as_bytes(), None, &mut buf)
            .map_err(|e| format!("X.224 confirm: {e}"))?;
        let should = ironrdp_tokio::skip_connect_begin(&mut connector);
        let upgraded = ironrdp_tokio::mark_as_upgraded(should, &mut connector);
        let key = crate::pin::public_key(server_cert_chain.first().ok_or("no certificate")?.as_bytes())
            .map_err(|_| "certificate")?;

        // Raw RDP from here on, carried in frames.
        let (client, mut pump) = duplex(64 * 1024);
        let mut framed = ironrdp_tokio::TokioFramed::new(client);
        let mut no_network = NoNetwork;
        let finish = ironrdp_tokio::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut no_network,
            ServerName::from("ignored"),
            key,
            None,
        );
        let (mut pump_r, mut pump_w) = tokio::io::split(&mut pump);
        let up = async {
            let mut chunk = vec![0u8; 16 * 1024];
            loop {
                let n = pump_r.read(&mut chunk).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err::<(), String>("browser side closed".into());
                }
                frame::write(to_proxy, Kind::Browser, &chunk[..n])
                    .await
                    .map_err(|e| e.to_string())?;
            }
        };
        let down = async {
            loop {
                match frame::read(from_proxy).await {
                    Ok((Kind::Desktop, payload)) => {
                        pump_w.write_all(&payload).await.map_err(|e| e.to_string())?;
                    }
                    other => return Err::<(), String>(format!("from the proxy: {other:?}")),
                }
            }
        };
        tokio::select! {
            outcome = finish => outcome.map(|_| ()).map_err(|e| format!("connection sequence: {e}")),
            r = up => r,
            r = down => r,
        }
    }

    /// End to end against a real NLA server. `KEYBASH_PROXY_TEST` holds
    /// `address,certificate.pem,name,secret-file`, and the secret file the user
    /// name and the password on two lines. A trailing `,peer` names Keybash's
    /// test peer (`rdp-testpeer/`), which CI's proxy job runs; the test VM
    /// names Windows. Elsewhere the test says so and passes.
    #[test]
    fn a_browser_reaches_the_desktop_through_the_proxy() {
        let Ok(spec) = std::env::var("KEYBASH_PROXY_TEST") else {
            eprintln!("KEYBASH_PROXY_TEST unset: no NLA server to reach");
            return;
        };
        let parts: Vec<&str> = spec.strip_suffix(",peer").unwrap_or(&spec).split(',').collect();
        let [address, certificate, name, secret] = parts.as_slice() else {
            panic!("KEYBASH_PROXY_TEST must be address,certificate,name,secret-file");
        };
        let pem = std::fs::read(certificate).expect("certificate file");
        let trust = Trust {
            certificate: crate::pin::certificate(&pem).expect("one certificate"),
            name: crate::pin::name(name.as_bytes()).expect("name"),
        };
        let secret = std::fs::read_to_string(secret).expect("secret file");
        let (user, password) = secret.trim_end_matches('\n').split_once('\n').expect("two lines");
        let setup = crate::setup::parse(&crate::setup::encode(user, "", password, false)).expect("setup");
        let target: SocketAddr = address.parse().expect("address");
        let _turn = live_turn();
        run_async(async {
            let (mut to_proxy, mut proxy_in) = duplex(256 * 1024);
            let (mut proxy_out, mut from_proxy) = duplex(256 * 1024);
            let proxy = run(&mut proxy_in, &mut proxy_out, setup, &trust, target);
            let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::select! {
                    fail = proxy => Err(format!("the proxy ended first: {}", fail_word(&fail))),
                    r = browser(&mut to_proxy, &mut from_proxy) => r,
                }
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(e)) => panic!("{e}"),
                Err(_) => panic!("no desktop within 30 seconds"),
            }
        });
    }

    /// A fixed word for how the proxy ended, for test messages: the end
    /// itself is never printed.
    fn fail_word(fail: &Fail) -> &'static str {
        match fail {
            Fail::Quiet => "quietly",
            Fail::End(Ended::Credentials) => "credentials",
            Fail::End(Ended::Unreachable) => "unreachable",
            Fail::End(Ended::Remote) => "remote ended",
            Fail::Refused(_, refusal) => refusal.word(),
        }
    }

    /// What reaches Windows before TLS carries no account material: not the
    /// user name, not the domain, not the password.
    #[test]
    fn nothing_about_the_account_crosses_before_tls() {
        run_async(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
            let target = listener.local_addr().expect("addr");
            let peer = async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                let mut head = [0u8; 4];
                s.read_exact(&mut head).await.expect("TPKT");
                let mut body = vec![0u8; usize::from(u16::from_be_bytes([head[2], head[3]])) - 4];
                s.read_exact(&mut body).await.expect("X.224");
                body
            };
            let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
            let (mut proxy_out, _from) = duplex(64 * 1024);
            let (_, request) = rdcleanpath_request_from_browser();
            frame::write(&mut to_proxy, Kind::Browser, &request)
                .await
                .expect("write");
            let password = crate::setup::tests::test_password(13, 14, false);
            let setup = crate::setup::parse(&crate::setup::encode("kb-account-name", "KB-DOMAIN", &password, false))
                .expect("setup");
            let trust = Trust {
                certificate: crate::pin::tests::certificate_der(),
                name: Name::ExactLeaf,
            };
            let (_, sent) = tokio::join!(run(&mut proxy_in, &mut proxy_out, setup, &trust, target), peer);
            let crossed = |text: &[u8]| sent.windows(text.len()).any(|w| w == text);
            for (what, text) in [
                ("the user name", &b"kb-account-name"[..]),
                ("the domain", b"KB-DOMAIN"),
                ("the routing cookie", b"mstshash"),
            ] {
                assert!(!crossed(text), "{what} crossed before TLS: {sent:?}");
            }
            assert!(!crossed(password.as_bytes()), "the password crossed before TLS");
        });
    }

    #[test]
    fn a_wrong_certificate_ends_before_any_credential() {
        run_async(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
            let target = listener.local_addr().expect("addr");
            // A peer that confirms NLA in X.224, then answers TLS with a
            // certificate the pin does not name.
            let peer = async move {
                let (mut s, _) = listener.accept().await.expect("accept");
                let mut request = [0u8; 64];
                let _ = s.read(&mut request).await;
                let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
                    flags: nego::ResponseFlags::empty(),
                    protocol: nego::SecurityProtocol::HYBRID,
                }))
                .expect("confirm");
                let _ = s.write_all(&confirm).await;
                let mut rest = [0u8; 4096];
                let _ = s.read(&mut rest).await;
            };
            let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
            let (mut proxy_out, _from_proxy) = duplex(64 * 1024);
            let (_, request) = rdcleanpath_request_from_browser();
            frame::write(&mut to_proxy, Kind::Browser, &request)
                .await
                .expect("write");
            let password = crate::setup::tests::test_password(11, 12, false);
            let setup = crate::setup::parse(&crate::setup::encode("u", "", &password, false)).expect("setup");
            let trust = Trust {
                certificate: crate::pin::tests::certificate_der(),
                name: Name::ExactLeaf,
            };
            let (fail, ()) = tokio::join!(run(&mut proxy_in, &mut proxy_out, setup, &trust, target), peer);
            assert_eq!(fail, Fail::windows(Refusal::Certificate));
        });
    }

    #[test]
    fn requests_that_would_change_the_connection_are_refused() {
        run_async(async {
            let refused = |request: Vec<u8>| async move {
                let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
                let (mut proxy_out, _from) = duplex(64 * 1024);
                frame::write(&mut to_proxy, Kind::Browser, &request)
                    .await
                    .expect("write");
                let password = crate::setup::tests::test_password(12, 8, false);
                let setup = crate::setup::parse(&crate::setup::encode("u", "", &password, false)).expect("setup");
                let trust = Trust {
                    certificate: crate::pin::tests::certificate_der(),
                    name: Name::ExactLeaf,
                };
                // Port 9 on loopback: nothing should ever be dialled.
                run(
                    &mut proxy_in,
                    &mut proxy_out,
                    setup,
                    &trust,
                    "127.0.0.1:9".parse().expect("addr"),
                )
                .await
            };
            let (_, good) = rdcleanpath_request_from_browser();
            let x224 = |protocol| {
                encode_vec(&X224(nego::ConnectionRequest {
                    nego_data: None,
                    flags: nego::RequestFlags::empty(),
                    protocol,
                    correlation_info: None,
                }))
                .expect("x224")
            };
            let with = |x224: Vec<u8>, pcb: Option<String>| {
                RDCleanPathPdu::new_request(x224, "d".into(), "t".into(), pcb)
                    .and_then(|p| p.to_der())
                    .expect("request")
            };
            for (what, request, expected) in [
                (
                    "CredSSP from the browser",
                    with(x224(nego::SecurityProtocol::HYBRID), None),
                    Fail::browser(Refusal::SecurityNotTls),
                ),
                (
                    "TLS and CredSSP",
                    with(x224(nego::SecurityProtocol::SSL | nego::SecurityProtocol::HYBRID), None),
                    Fail::browser(Refusal::SecurityNotTls),
                ),
                (
                    "standard RDP security",
                    with(x224(nego::SecurityProtocol::empty()), None),
                    Fail::browser(Refusal::SecurityNotTls),
                ),
                (
                    "a preconnection blob",
                    with(x224(nego::SecurityProtocol::SSL), Some("blob".into())),
                    Fail::browser(Refusal::ConnectionChange),
                ),
                // RDCleanPath's detection waits for more of what is not DER,
                // until the browser's time runs out.
                (
                    "not DER",
                    b"GET / HTTP/1.1\r\n\r\n".to_vec(),
                    Fail::browser(Refusal::HandshakeTooSlow),
                ),
                ("cut short", good[..good.len() - 1].to_vec(), Fail::Quiet),
            ] {
                let fail = if what == "cut short" {
                    // The rest never comes: the browser leaves.
                    let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
                    let (mut proxy_out, _from) = duplex(64 * 1024);
                    frame::write(&mut to_proxy, Kind::Browser, &request)
                        .await
                        .expect("write");
                    drop(to_proxy);
                    let password = crate::setup::tests::test_password(12, 8, false);
                    let setup = crate::setup::parse(&crate::setup::encode("u", "", &password, false)).expect("setup");
                    let trust = Trust {
                        certificate: crate::pin::tests::certificate_der(),
                        name: Name::ExactLeaf,
                    };
                    run(
                        &mut proxy_in,
                        &mut proxy_out,
                        setup,
                        &trust,
                        "127.0.0.1:9".parse().expect("addr"),
                    )
                    .await
                } else {
                    refused(request).await
                };
                // Each refusal names the browser and what it sent.
                assert_eq!(fail, expected, "{what}: {}", fail_word(&fail));
            }
        });
    }

    /// One live desktop at a time: the test peer serves one session, and a
    /// second session for the same account would take Windows' over.
    static LIVE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    fn live_turn() -> std::sync::MutexGuard<'static, ()> {
        LIVE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The NLA server named in `KEYBASH_PROXY_TEST`, if any (see above).
    fn live_server() -> Option<(Trust, Setup, SocketAddr)> {
        let spec = std::env::var("KEYBASH_PROXY_TEST").ok()?;
        let parts: Vec<&str> = spec.strip_suffix(",peer").unwrap_or(&spec).split(',').collect();
        let [address, certificate, name, secret] = parts.as_slice() else {
            panic!("KEYBASH_PROXY_TEST must be address,certificate,name,secret-file");
        };
        let pem = std::fs::read(certificate).expect("certificate file");
        let trust = Trust {
            certificate: crate::pin::certificate(&pem).expect("one certificate"),
            name: crate::pin::name(name.as_bytes()).expect("name"),
        };
        let secret = std::fs::read_to_string(secret).expect("secret file");
        let (user, password) = secret.trim_end_matches('\n').split_once('\n').expect("two lines");
        let setup = crate::setup::parse(&crate::setup::encode(user, "", password, false)).expect("setup");
        Some((trust, setup, address.parse().expect("address")))
    }

    /// A whole desktop through the proxy: the browser opens `drdynvc` with
    /// display control, Windows offers its dynamic channels, the browser opens
    /// display control and refuses the rest, and every PDU passes the checks.
    /// A monitor layout inside the bounds passes; one outside them ends the
    /// session as "refused".
    #[test]
    fn dynamic_channels_and_display_layouts_follow_the_rules() {
        use ironrdp_displaycontrol::client::DisplayControlClient;
        use ironrdp_dvc::DrdynvcClient;
        use ironrdp_session::ActiveStageOutput;

        let Some((trust, setup, target)) = live_server() else {
            eprintln!("KEYBASH_PROXY_TEST unset: no NLA server to reach");
            return;
        };
        let _turn = live_turn();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let mut connector = ClientConnector::new(
                crate::policy::tests::browser_config(1600, 900, 100),
                "127.0.0.1:0".parse().expect("addr"),
            );
            connector.attach_static_channel(
                DrdynvcClient::new().with_dynamic_channel(DisplayControlClient::new(|_| Ok(Vec::new()))),
            );
            let (proxy, mut framed, mut stage) = live_desktop(connector, setup, trust, target).await;
            let mut image = ironrdp_session::image::DecodedImage::new(
                ironrdp_graphics::image_processing::PixelFormat::RgbA32,
                1600,
                900,
            );

            // Run the session until display control is ready, then a while.
            let mut layout_sent = false;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
            let mut quiet_until = None;
            loop {
                assert!(!proxy.is_finished(), "the proxy ended a valid session");
                if tokio::time::Instant::now() > deadline {
                    panic!("display control never became ready");
                }
                if let Some(until) = quiet_until
                    && tokio::time::Instant::now() > until
                {
                    break;
                }
                if !layout_sent && stage.display_control_capabilities().is_some() {
                    let frame = stage
                        .encode_resize(1280, 720, Some(100), None)
                        .expect("ready")
                        .expect("encode");
                    framed.write_all(&frame).await.expect("layout");
                    layout_sent = true;
                    quiet_until = Some(tokio::time::Instant::now() + std::time::Duration::from_secs(3));
                }
                let Ok(read) = tokio::time::timeout(std::time::Duration::from_millis(200), framed.read_pdu()).await
                else {
                    continue;
                };
                let (action, frame) = read.expect("read");
                for out in stage.process(&mut image, action, &frame, None).expect("process") {
                    if let ActiveStageOutput::ResponseFrame(frame) = out {
                        framed.write_all(&frame).await.expect("response");
                    }
                }
            }
            assert!(!proxy.is_finished(), "the proxy ended after a layout inside the bounds");

            // Twice the full-HD width at 100%: the proxy must end it.
            let frame = stage
                .encode_resize(3840, 2160, Some(100), None)
                .expect("ready")
                .expect("encode");
            framed.write_all(&frame).await.expect("layout");
            let fail = tokio::time::timeout(std::time::Duration::from_secs(5), proxy)
                .await
                .expect("the proxy let a layout outside the bounds pass")
                .expect("proxy task");
            assert_eq!(fail, Fail::browser(Refusal::DisplayLayoutOutOfBounds));
        });
    }

    type LiveFramed = ironrdp_tokio::TokioFramed<tokio::io::DuplexStream>;

    /// Connects `connector`, its static channels attached, to the live server
    /// through the proxy, as the page will: RDCleanPath, then raw RDP in
    /// frames. Runs in a `LocalSet`; returns the proxy's task, the browser's
    /// stream and its active stage.
    async fn live_desktop(
        mut connector: ClientConnector,
        setup: Setup,
        trust: Trust,
        target: SocketAddr,
    ) -> (tokio::task::JoinHandle<Fail>, LiveFramed, ironrdp_session::ActiveStage) {
        use ironrdp_session::ActiveStageBuilder;

        let (mut to_proxy, mut proxy_in) = duplex(256 * 1024);
        let (mut proxy_out, mut from_proxy) = duplex(256 * 1024);
        let proxy =
            tokio::task::spawn_local(async move { run(&mut proxy_in, &mut proxy_out, setup, &trust, target).await });
        let mut buf = WriteBuf::new();
        connector.step_no_input(&mut buf).expect("X.224 request");
        let request = RDCleanPathPdu::new_request(buf.filled().to_vec(), "x".into(), "x".into(), None)
            .and_then(|pdu| pdu.to_der())
            .expect("request");
        frame::write(&mut to_proxy, Kind::Browser, &request)
            .await
            .expect("request");
        let (_, payload) = frame::read(&mut from_proxy).await.expect("response");
        let Ok(RDCleanPathMessage::Response {
            x224_connection_response,
            server_cert_chain,
            ..
        }) = RDCleanPathPdu::from_der(&payload)
            .map_err(|_| ())
            .and_then(|p| p.into_message().map_err(|_| ()))
        else {
            panic!("not an RDCleanPath response");
        };
        buf.clear();
        connector
            .step(x224_connection_response.as_bytes(), None, &mut buf)
            .expect("confirm");
        let should = ironrdp_tokio::skip_connect_begin(&mut connector);
        let upgraded = ironrdp_tokio::mark_as_upgraded(should, &mut connector);
        let key = crate::pin::public_key(server_cert_chain[0].as_bytes()).expect("key");

        // The page's own pumps: raw RDP one side, frames the other.
        let (client, pump) = duplex(256 * 1024);
        let (mut pump_r, mut pump_w) = tokio::io::split(pump);
        tokio::task::spawn_local(async move {
            let mut chunk = vec![0u8; 16 * 1024];
            while let Ok(n) = pump_r.read(&mut chunk).await {
                if n == 0 || frame::write(&mut to_proxy, Kind::Browser, &chunk[..n]).await.is_err() {
                    break;
                }
            }
        });
        tokio::task::spawn_local(async move {
            while let Ok((Kind::Desktop, payload)) = frame::read(&mut from_proxy).await {
                if pump_w.write_all(&payload).await.is_err() {
                    break;
                }
            }
        });

        let mut framed = ironrdp_tokio::TokioFramed::new(client);
        let mut no_network = NoNetwork;
        let outcome = ironrdp_tokio::connect_finalize(
            upgraded,
            connector,
            &mut framed,
            &mut no_network,
            ServerName::from("x"),
            key,
            None,
        )
        .await
        .expect("connection sequence");
        let ironrdp_connector::ConnectionOutcome::Connected(result) = outcome else {
            panic!("redirected");
        };
        let stage = ActiveStageBuilder {
            static_channels: result.static_channels,
            user_channel_id: result.user_channel_id,
            io_channel_id: result.io_channel_id,
            message_channel_id: result.message_channel_id,
            share_id: result.share_id,
            compression_type: result.compression_type,
            enable_server_pointer: result.enable_server_pointer,
            pointer_software_rendering: result.pointer_software_rendering,
        }
        .build();
        (proxy, framed, stage)
    }

    /// What IronRDP's clipboard client heard, as a page's backend would.
    #[derive(Debug, Default)]
    struct Heard {
        format_list_asked: bool,
        negotiated: Option<ironrdp_cliprdr::pdu::ClipboardGeneralCapabilityFlags>,
        list_accepted: Option<bool>,
        remote_formats: Vec<Vec<u32>>,
        asked_for_data: Vec<u32>,
        data: Vec<Option<String>>,
        files_or_locks: usize,
    }
    ironrdp_core::impl_as_any!(Heard);

    impl ironrdp_cliprdr::backend::CliprdrBackend for Heard {
        fn temporary_directory(&self) -> &str {
            "C:\\keybash-test"
        }
        fn client_capabilities(&self) -> ironrdp_cliprdr::pdu::ClipboardGeneralCapabilityFlags {
            // Ask for everything; the proxy must leave long names only.
            ironrdp_cliprdr::pdu::ClipboardGeneralCapabilityFlags::all()
        }
        fn on_ready(&mut self) {}
        fn on_request_format_list(&mut self) {
            self.format_list_asked = true;
        }
        fn on_format_list_response(&mut self, ok: bool) {
            self.list_accepted = Some(ok);
        }
        fn on_process_negotiated_capabilities(
            &mut self,
            capabilities: ironrdp_cliprdr::pdu::ClipboardGeneralCapabilityFlags,
        ) {
            self.negotiated = Some(capabilities);
        }
        fn on_remote_copy(&mut self, formats: &[ironrdp_cliprdr::pdu::ClipboardFormat]) {
            self.remote_formats
                .push(formats.iter().map(|f| f.id().value()).collect());
        }
        fn on_format_data_request(&mut self, request: ironrdp_cliprdr::pdu::FormatDataRequest) {
            self.asked_for_data.push(request.format.value());
        }
        fn on_format_data_response(&mut self, response: ironrdp_cliprdr::pdu::FormatDataResponse<'_>) {
            self.data
                .push((!response.is_error()).then(|| response.to_unicode_string().unwrap_or_default()));
        }
        fn on_file_contents_request(&mut self, _: ironrdp_cliprdr::pdu::FileContentsRequest) {
            self.files_or_locks += 1;
        }
        fn on_file_contents_response(&mut self, _: ironrdp_cliprdr::pdu::FileContentsResponse<'_>) {
            self.files_or_locks += 1;
        }
        fn on_lock(&mut self, _: ironrdp_cliprdr::pdu::LockDataId) {
            self.files_or_locks += 1;
        }
        fn on_unlock(&mut self, _: ironrdp_cliprdr::pdu::LockDataId) {
            self.files_or_locks += 1;
        }
    }

    /// The clipboard against Windows through the proxy, with the account's
    /// clipboard allowed: capabilities come back with long names only, the
    /// browser's text offer is accepted, its temporary directory never reaches
    /// Windows, and text pasted on the desktop crosses both ways when Windows
    /// asks for it. Nothing about files or locks reaches the browser.
    #[test]
    fn clipboard_text_crosses_and_nothing_else() {
        use ironrdp_cliprdr::CliprdrClient;
        use ironrdp_cliprdr::pdu::{ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags};
        use ironrdp_pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
        use ironrdp_session::ActiveStageOutput;

        let Some((trust, mut setup, target)) = live_server() else {
            eprintln!("KEYBASH_PROXY_TEST unset: no NLA server to reach");
            return;
        };
        if std::env::var("KEYBASH_PROXY_TEST").is_ok_and(|spec| spec.ends_with(",peer")) {
            eprintln!("the clipboard test drives Windows' own desktop, which the test peer has not");
            return;
        }
        let _turn = live_turn();
        setup.clipboard = true;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("runtime");
        let local = tokio::task::LocalSet::new();
        local.block_on(&runtime, async move {
            let mut connector = ClientConnector::new(
                crate::policy::tests::browser_config(1600, 900, 100),
                "127.0.0.1:0".parse().expect("addr"),
            );
            connector.attach_static_channel(CliprdrClient::new(Box::new(Heard::default())));
            let (proxy, mut framed, mut stage) = live_desktop(connector, setup, trust, target).await;
            let mut image = ironrdp_session::image::DecodedImage::new(
                ironrdp_graphics::image_processing::PixelFormat::RgbA32,
                1600,
                900,
            );
            // The page offers this text. On the desktop, Win+R runs a command that
            // reads the clipboard (Windows asks the browser for the text) and
            // writes it back with " back" (Windows offers text). The page then
            // pastes it.
            let text = "Keybash clipboard: héllo 🙂";
            let command =
                "powershell -NoProfile -WindowStyle Hidden -Command \"Set-Clipboard ((Get-Clipboard -Raw) + ' back')\"";
            let key = |code: u8, flags: KeyboardFlags| FastPathInputEvent::KeyboardEvent(flags, code);
            let win_r = vec![
                key(0x5B, KeyboardFlags::EXTENDED),
                key(0x13, KeyboardFlags::empty()),
                key(0x13, KeyboardFlags::RELEASE),
                key(0x5B, KeyboardFlags::EXTENDED | KeyboardFlags::RELEASE),
            ];
            let escape = vec![key(0x01, KeyboardFlags::empty()), key(0x01, KeyboardFlags::RELEASE)];
            let enter = vec![key(0x1C, KeyboardFlags::empty()), key(0x1C, KeyboardFlags::RELEASE)];
            let units: Vec<u16> = command.encode_utf16().collect();
            let typing: Vec<Vec<FastPathInputEvent>> = units
                .chunks(8)
                .map(|part| {
                    part.iter()
                        .flat_map(|&unit| {
                            [
                                FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), unit),
                                FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, unit),
                            ]
                        })
                        .collect()
                })
                .collect();
            let mut keys = std::collections::VecDeque::new();

            let (mut copied, mut typed, mut pasted, mut answered) = (false, false, false, 0);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(45);
            let mut quiet_until = None;
            loop {
                assert!(!proxy.is_finished(), "the proxy ended a valid session");
                let now = tokio::time::Instant::now();
                if quiet_until.is_some_and(|until| now > until) {
                    break;
                }
                let client = stage.get_svc_processor_mut::<CliprdrClient>().expect("cliprdr");
                let heard = client.downcast_backend::<Heard>().expect("backend");
                assert!(
                    now < deadline,
                    "the clipboard never came back: {heard:?}, typed {typed}, answered {answered}, pasted {pasted}"
                );
                let (asked, accepted, requests) =
                    (heard.format_list_asked, heard.list_accepted, heard.asked_for_data.len());
                let offered = heard.remote_formats.last().is_some_and(|formats| formats.contains(&13));
                let back = heard.data.iter().flatten().any(|data| data.contains(" back"));
                let messages = if asked && !copied {
                    copied = true;
                    Some(client.initiate_copy(&[ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]))
                } else if requests > answered {
                    answered += 1;
                    Some(client.submit_format_data(ironrdp_cliprdr::pdu::FormatDataResponse::new_unicode_string(text)))
                } else if offered && answered > 0 && !pasted {
                    pasted = true;
                    Some(client.initiate_paste(ClipboardFormatId::CF_UNICODETEXT))
                } else {
                    None
                };
                if let Some(messages) = messages {
                    let frame = stage
                        .process_svc_processor_messages(messages.expect("clipboard message"))
                        .expect("encode");
                    framed.write_all(&frame).await.expect("clipboard");
                }
                if accepted == Some(true) && !typed {
                    // As a person would: close whatever dialog is open, Win+R,
                    // type in short bursts, then Enter.
                    typed = true;
                    let at = |ms: u64| now + std::time::Duration::from_millis(ms);
                    keys.push_back((at(3000), escape.clone()));
                    keys.push_back((at(3500), win_r.clone()));
                    for (i, part) in typing.iter().enumerate() {
                        keys.push_back((at(5500 + 150 * i as u64), part.clone()));
                    }
                    keys.push_back((at(5500 + 150 * typing.len() as u64 + 1000), enter.clone()));
                }
                if keys.front().is_some_and(|(at, _)| now >= *at)
                    && let Some((_, events)) = keys.pop_front()
                {
                    for out in stage.process_fastpath_input(&mut image, &events).expect("input") {
                        if let ActiveStageOutput::ResponseFrame(frame) = out {
                            framed.write_all(&frame).await.expect("input");
                        }
                    }
                }
                if back && quiet_until.is_none() {
                    quiet_until = Some(now + std::time::Duration::from_secs(2));
                }
                let Ok(read) = tokio::time::timeout(std::time::Duration::from_millis(200), framed.read_pdu()).await
                else {
                    continue;
                };
                let (action, frame) = read.expect("read");
                for out in stage.process(&mut image, action, &frame, None).expect("process") {
                    if let ActiveStageOutput::ResponseFrame(frame) = out {
                        framed.write_all(&frame).await.expect("response");
                    }
                }
            }
            assert!(!proxy.is_finished(), "the proxy ended a valid clipboard");
            let client = stage.get_svc_processor_mut::<CliprdrClient>().expect("cliprdr");
            let heard = client.downcast_backend::<Heard>().expect("backend");
            eprintln!("{heard:?}");
            assert_eq!(
                heard.negotiated,
                Some(ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES)
            );
            assert_eq!(heard.list_accepted, Some(true));
            assert!(!heard.asked_for_data.is_empty(), "Windows read the browser's text");
            assert!(heard.asked_for_data.iter().all(|&id| id == 13), "only text asked for");
            assert!(
                heard
                    .remote_formats
                    .iter()
                    .all(|formats| formats.is_empty() || formats == &[13]),
                "Windows offers text alone"
            );
            assert_eq!(heard.files_or_locks, 0);
            let pasted = heard.data.iter().flatten().find(|data| data.contains(" back"));
            assert_eq!(pasted.map(|data| data.trim_end()), Some(&*format!("{text} back")));
        });
    }

    /// What Windows reads once a relay between pipes is over, and how it ended:
    /// the browser may send one frame, and each side may stay or go away.
    async fn relay_end(browser_sends: Option<Kind>, browser_stays: bool, windows_stays: bool) -> (Fail, Vec<u8>) {
        let (mut browser, mut proxy_in) = duplex(64 * 1024);
        let (mut proxy_out, _browser_reads) = duplex(64 * 1024);
        let (windows_writes, mut from_windows) = duplex(64 * 1024);
        let (mut to_windows, mut windows_reads) = duplex(64 * 1024);
        if let Some(kind) = browser_sends {
            frame::write(&mut browser, kind, b"x").await.expect("browser frame");
        }
        let _browser = browser_stays.then_some(browser);
        let _windows = windows_stays.then_some(windows_writes);
        let channels = RefCell::new(Channels::new(vec!["drdynvc".into()], false));
        let fail = relay(
            &mut proxy_in,
            &mut proxy_out,
            &mut from_windows,
            &mut to_windows,
            &channels,
            &[],
        )
        .await;
        drop(to_windows);
        let mut heard = Vec::new();
        windows_reads.read_to_end(&mut heard).await.expect("Windows' side");
        (fail, heard)
    }

    fn ultimatum() -> Vec<u8> {
        encode_vec(&X224(McsMessage::DisconnectProviderUltimatum(
            DisconnectProviderUltimatum::from_reason(DisconnectReason::UserRequested),
        )))
        .expect("encode")
    }

    /// A browser that goes away, or one the relay refuses, ends the session
    /// with Windows as a client does: the MCS Disconnect Provider Ultimatum
    /// (user requested), then the close, and nothing else. A desktop opened
    /// again at once then gets its picture.
    #[test]
    fn an_end_on_keybash_side_says_goodbye_to_windows() {
        run_async(async {
            // The browser goes away; the browser sends what only Windows may.
            let gateway_frame = Fail::keybash(Refusal::GatewayFrame);
            for (sends, stays, end) in [(None, false, Fail::Quiet), (Some(Kind::Desktop), true, gateway_frame)] {
                let (fail, heard) = relay_end(sends, stays, true).await;
                assert_eq!(fail, end);
                let X224(message) = decode::<X224<McsMessage<'_>>>(&heard).expect("an MCS PDU");
                assert!(matches!(message, McsMessage::DisconnectProviderUltimatum(_)));
                assert_eq!(heard, ultimatum(), "Windows heard more than the ultimatum");
            }
        });
    }

    /// When Windows ends the session, nothing more is written to it.
    #[test]
    fn an_end_from_windows_says_nothing_more() {
        run_async(async {
            let (fail, heard) = relay_end(None, true, false).await;
            assert_eq!(fail, Fail::End(Ended::Remote));
            assert!(heard.is_empty(), "the relay wrote to a Windows that had ended");
        });
    }

    /// A TPKT header that claims 4 bytes: shorter than any PDU.
    const TOO_SHORT: [u8; 4] = [3, 0, 0, 4];

    /// How a relay ends when the browser, or Windows, sends `bytes`.
    async fn relay_refusal(from_browser: Option<&[u8]>, from_windows: Option<&[u8]>) -> Fail {
        let (mut browser, mut proxy_in) = duplex(64 * 1024);
        let (mut proxy_out, _browser_reads) = duplex(64 * 1024);
        let (mut windows_writes, mut from_windows_pipe) = duplex(64 * 1024);
        let (mut to_windows, _windows_reads) = duplex(64 * 1024);
        if let Some(bytes) = from_browser {
            frame::write(&mut browser, Kind::Browser, bytes).await.expect("browser");
        }
        if let Some(bytes) = from_windows {
            windows_writes.write_all(bytes).await.expect("Windows");
        }
        let channels = RefCell::new(Channels::new(vec!["drdynvc".into()], false));
        relay(
            &mut proxy_in,
            &mut proxy_out,
            &mut from_windows_pipe,
            &mut to_windows,
            &channels,
            &[],
        )
        .await
    }

    /// A refusal names the side that sent what was refused, the same bytes
    /// either way, and what it was.
    #[test]
    fn a_refusal_names_the_side_that_sent_it() {
        run_async(async {
            assert_eq!(
                relay_refusal(Some(&TOO_SHORT), None).await,
                Fail::browser(Refusal::PduFraming)
            );
            assert_eq!(
                relay_refusal(None, Some(&TOO_SHORT)).await,
                Fail::windows(Refusal::PduFraming)
            );
            // Bytes the browser sent before the relay, after its Connect
            // Initial, are the browser's too.
            let (_browser, mut proxy_in) = duplex(1024);
            let (mut proxy_out, _reads) = duplex(1024);
            let (_windows, mut from_windows) = duplex(1024);
            let (mut to_windows, _heard) = duplex(1024);
            let channels = RefCell::new(Channels::new(Vec::new(), false));
            let fail = relay(
                &mut proxy_in,
                &mut proxy_out,
                &mut from_windows,
                &mut to_windows,
                &channels,
                &TOO_SHORT,
            )
            .await;
            assert_eq!(fail, Fail::browser(Refusal::PduFraming));
        });
    }

    /// A handshake that runs out of time names the side it waited on: the
    /// browser that never sends its request, or Windows that never answers.
    #[test]
    fn a_stalled_handshake_names_the_side_it_waited_on() {
        run_async(async {
            let trust = || Trust {
                certificate: crate::pin::tests::certificate_der(),
                name: Name::ExactLeaf,
            };
            let setup = || {
                let password = crate::setup::tests::test_password(12, 9, false);
                crate::setup::parse(&crate::setup::encode("u", "", &password, false)).expect("setup")
            };
            let silent_browser = async {
                let (_to_proxy, mut proxy_in) = duplex(1024);
                let (mut proxy_out, _from) = duplex(1024);
                let (trust, target) = (trust(), "127.0.0.1:9".parse().expect("addr"));
                run(&mut proxy_in, &mut proxy_out, setup(), &trust, target).await
            };
            let silent_windows = async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
                let target = listener.local_addr().expect("addr");
                let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
                let (mut proxy_out, _from) = duplex(64 * 1024);
                let (_, request) = rdcleanpath_request_from_browser();
                frame::write(&mut to_proxy, Kind::Browser, &request)
                    .await
                    .expect("write");
                let trust = trust();
                let proxy = run(&mut proxy_in, &mut proxy_out, setup(), &trust, target);
                // Windows takes the connection and says nothing.
                let (fail, accepted) = tokio::join!(proxy, listener.accept());
                drop(accepted);
                fail
            };
            let (browser, windows) = tokio::join!(silent_browser, silent_windows);
            assert_eq!(browser, Fail::browser(Refusal::HandshakeTooSlow));
            assert_eq!(windows, Fail::windows(Refusal::HandshakeTooSlow));
        });
    }

    /// How the handshake ends when Windows answers the X.224 request with
    /// `answer` and then waits.
    async fn windows_answers(answer: Vec<u8>) -> Fail {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let target = listener.local_addr().expect("addr");
        let windows = async move {
            let (mut s, _) = listener.accept().await.expect("accept");
            let mut request = [0u8; 64];
            let _ = s.read(&mut request).await;
            s.write_all(&answer).await.expect("answer");
            let mut rest = [0u8; 4096];
            let _ = s.read(&mut rest).await;
        };
        let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
        let (mut proxy_out, _from_proxy) = duplex(64 * 1024);
        let (_, request) = rdcleanpath_request_from_browser();
        frame::write(&mut to_proxy, Kind::Browser, &request)
            .await
            .expect("write");
        let password = crate::setup::tests::test_password(10, 12, false);
        let setup = crate::setup::parse(&crate::setup::encode("u", "", &password, false)).expect("setup");
        let trust = Trust {
            certificate: crate::pin::tests::certificate_der(),
            name: Name::ExactLeaf,
        };
        let (fail, ()) = tokio::join!(run(&mut proxy_in, &mut proxy_out, setup, &trust, target), windows);
        fail
    }

    /// Windows that answers without NLA, as it does with TLS alone, standard
    /// RDP security, or a negotiation failure, is named so, before TLS; an
    /// answer that is no Connection Confirm at all is the confirm's fault.
    #[test]
    fn windows_without_nla_is_named_so() {
        run_async(async {
            let selects = |protocol| {
                encode_vec(&X224(nego::ConnectionConfirm::Response {
                    flags: nego::ResponseFlags::empty(),
                    protocol,
                }))
                .expect("confirm")
            };
            // RDP_NEG_FAILURE (type 3), SSL_NOT_ALLOWED_BY_SERVER (2).
            let failure = vec![3, 0, 0, 19, 14, 0xd0, 0, 0, 0, 1, 0, 3, 0, 8, 0, 2, 0, 0, 0];
            // A data PDU where the Connection Confirm should be.
            let not_a_confirm = vec![3, 0, 0, 11, 2, 0xf0, 0x80, 1, 2, 3, 4];
            for (what, answer, expected) in [
                (
                    "standard RDP security",
                    selects(nego::SecurityProtocol::empty()),
                    Fail::windows(Refusal::NlaNotSelected),
                ),
                (
                    "TLS alone",
                    selects(nego::SecurityProtocol::SSL),
                    Fail::windows(Refusal::NlaNotSelected),
                ),
                ("a negotiation failure", failure, Fail::windows(Refusal::NlaNotSelected)),
                ("no confirm", not_a_confirm, Fail::windows(Refusal::X224Confirm)),
            ] {
                let fail = windows_answers(answer).await;
                assert_eq!(fail, expected, "{what}: {}", fail_word(&fail));
            }
        });
    }

    /// The Ended frame holds fixed codes and nothing else: one byte for an
    /// end, three for a refusal, none when the session ended quietly.
    #[test]
    fn the_ended_frame_holds_codes_only() {
        assert_eq!(Fail::End(Ended::Credentials).ended(), Some(vec![1]));
        assert_eq!(Fail::End(Ended::Unreachable).ended(), Some(vec![3]));
        assert_eq!(Fail::End(Ended::Remote).ended(), Some(vec![6]));
        assert_eq!(Fail::Quiet.ended(), None);
        assert_eq!(
            Fail::windows(Refusal::ClipboardFormatList).ended(),
            Some(vec![5, 2, 31])
        );
        for side in [Side::Browser, Side::Windows, Side::Keybash] {
            for &refusal in Refusal::ALL {
                assert_eq!(
                    Fail::Refused(side, refusal).ended(),
                    Some(vec![frame::REFUSED, side as u8, refusal as u8])
                );
            }
        }
    }
}
