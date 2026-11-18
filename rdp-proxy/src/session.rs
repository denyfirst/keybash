//! One desktop: the browser's RDCleanPath request, X.224, TLS and NLA with
//! Windows, the checked Connect Initial, then the relay.

use std::net::SocketAddr;

use ironrdp_connector::credssp::CredsspSequence;
use ironrdp_connector::sspi::generator::NetworkRequest;
use ironrdp_connector::{ClientConnector, ConnectorResult, Credentials, Sequence as _, ServerName};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::nego;
use ironrdp_pdu::x224::X224;
use ironrdp_rdcleanpath::{DetectionResult, RDCleanPathMessage, RDCleanPathPdu};
use ironrdp_tokio::FramedWrite as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::TcpStream;

use std::cell::RefCell;

use crate::channels::{Channels, Pass, Splitter};
use crate::frame::{self, Ended, FrameError, Kind};
use crate::policy;
use crate::setup::Setup;

/// The browser's RDCleanPath request is small; anything larger is refused.
const MAX_REQUEST: usize = 16 * 1024;

/// The pinned certificate (DER) and the name Windows is known by.
#[derive(Clone)]
pub struct Trust {
    pub certificate: Vec<u8>,
    pub name: crate::pin::Name,
}

/// How a session ended: with a word for the gateway, or quietly because the
/// gateway or the browser went away.
#[derive(Debug, PartialEq, Eq)]
pub enum Fail {
    End(Ended),
    Quiet,
}

impl From<FrameError> for Fail {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Closed => Fail::Quiet,
            FrameError::Malformed => Fail::End(Ended::Refused),
        }
    }
}

const REFUSED: Fail = Fail::End(Ended::Refused);

/// Appends the next browser message; anything but a browser frame ends it.
async fn browser_bytes<R: AsyncRead + Unpin>(gateway: &mut R, into: &mut Vec<u8>, most: usize) -> Result<(), Fail> {
    let (kind, payload) = frame::read(gateway).await?;
    if kind != Kind::Browser || into.len() + payload.len() > most {
        return Err(REFUSED);
    }
    into.extend_from_slice(&payload);
    Ok(())
}

/// Reads the browser's RDCleanPath request and returns its X.224 request.
async fn rdcleanpath_request<R: AsyncRead + Unpin>(gateway: &mut R, inbuf: &mut Vec<u8>) -> Result<Vec<u8>, Fail> {
    let request = loop {
        match RDCleanPathPdu::detect(inbuf) {
            DetectionResult::Detected { total_length, .. } if total_length > MAX_REQUEST => return Err(REFUSED),
            DetectionResult::Detected { total_length, .. } if inbuf.len() >= total_length => {
                break inbuf.drain(..total_length).collect::<Vec<u8>>();
            }
            DetectionResult::Detected { .. } | DetectionResult::NotEnoughBytes => {}
            DetectionResult::Failed => return Err(REFUSED),
        }
        browser_bytes(gateway, inbuf, MAX_REQUEST).await?;
    };
    let message = RDCleanPathPdu::from_der(&request)
        .map_err(|_| REFUSED)?
        .into_message()
        .map_err(|_| REFUSED)?;
    // The destination and the token are not used: the target and the access
    // are the gateway's. Anything that would change the connection is refused.
    let RDCleanPathMessage::Request {
        preconnection_blob: None,
        server_auth: None,
        x224_connection_request,
        ..
    } = message
    else {
        return Err(REFUSED);
    };
    let x224 = x224_connection_request.as_bytes().to_vec();
    let X224(request) = decode::<X224<nego::ConnectionRequest>>(&x224).map_err(|_| REFUSED)?;
    if request.protocol != nego::SecurityProtocol::SSL {
        return Err(REFUSED);
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
    let clipboard = setup.clipboard;
    let (user, domain) = (setup.user.clone(), setup.domain.clone());
    let handshake = tokio::time::timeout(HANDSHAKE_WAIT, handshake(gateway_in, gateway_out, setup, trust, target));
    let (tls, checked, names, rest) = match handshake.await {
        Ok(Ok(ready)) => ready,
        Ok(Err(fail)) => return fail,
        Err(_) => return REFUSED,
    };
    let (mut from_windows, mut to_windows) = tokio::io::split(tls);
    if to_windows.write_all(&checked).await.is_err() {
        return Fail::End(Ended::Remote);
    }

    // The relay: whole PDUs each way, each checked against the channels
    // before it passes (crate::channels). Both directions run in this one
    // task, so they share the state without locks.
    let channels = RefCell::new(Channels::new(names, clipboard).for_account(&user, &domain));
    let mut browser = Splitter::default();
    if let Err(fail) = pass_browser_bytes(&rest, &mut browser, &channels, &mut to_windows).await {
        return fail;
    }
    tokio::select! {
        fail = upstream(gateway_in, &mut to_windows, &mut browser, &channels) => fail,
        fail = downstream(&mut from_windows, gateway_out, &channels) => fail,
    }
}

/// Splits browser bytes into PDUs, checks each, and sends the ones that pass.
async fn pass_browser_bytes<W: AsyncWrite + Unpin>(
    bytes: &[u8],
    splitter: &mut Splitter,
    channels: &RefCell<Channels>,
    windows: &mut W,
) -> Result<(), Fail> {
    let pdus = splitter.push(bytes).map_err(|_| REFUSED)?;
    let mut out = Vec::new();
    for (action, pdu) in &pdus {
        match channels.borrow_mut().browser_pdu(*action, pdu).map_err(|_| REFUSED)? {
            Pass::Unchanged => out.extend_from_slice(pdu),
            Pass::Instead(instead) => instead.iter().for_each(|p| out.extend_from_slice(p)),
        }
    }
    windows.write_all(&out).await.map_err(|_| Fail::End(Ended::Remote))?;
    windows.flush().await.map_err(|_| Fail::End(Ended::Remote))
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
async fn handshake<R, W>(
    gateway_in: &mut R,
    gateway_out: &mut W,
    setup: Setup,
    trust: &Trust,
    target: SocketAddr,
) -> Result<Ready, Fail>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let clipboard = setup.clipboard;
    let mut inbuf = Vec::new();
    rdcleanpath_request(gateway_in, &mut inbuf).await?;

    // Windows: X.224 asking for NLA, TLS against the pinned certificate, then
    // CredSSP with the credentials only this process holds.
    let tcp = TcpStream::connect(target)
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    tcp.set_nodelay(true).map_err(|_| Fail::End(Ended::Unreachable))?;
    // Nothing about the account crosses the network before TLS. IronRDP puts
    // the user name in the X.224 request as a routing cookie, so the request
    // is made by a connector that has no user name; the connector with the
    // credentials then follows the same confirmation, and its own request is
    // never sent.
    let local = "127.0.0.1:0".parse().map_err(|_| REFUSED)?;
    let mut nameless = ClientConnector::new(crate::config::connector_config(), local);
    let mut framed = ironrdp_tokio::TokioFramed::new(tcp);
    let mut buf = WriteBuf::new();
    nameless.step_no_input(&mut buf).map_err(|_| REFUSED)?;
    framed
        .write_all(buf.filled())
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    let hint = nameless.next_pdu_hint().ok_or(REFUSED)?;
    let confirm = framed
        .read_by_hint(hint)
        .await
        .map_err(|_| Fail::End(Ended::Unreachable))?;
    let mut connector = ClientConnector::new(windows_config(&setup), local);
    let mut unsent = WriteBuf::new();
    connector.step_no_input(&mut unsent).map_err(|_| REFUSED)?;
    drop(unsent);
    buf.clear();
    connector.step(&confirm, None, &mut buf).map_err(|_| REFUSED)?;
    let X224(nego::ConnectionConfirm::Response {
        flags,
        protocol: selected,
    }) = decode::<X224<nego::ConnectionConfirm>>(&confirm).map_err(|_| REFUSED)?
    else {
        return Err(REFUSED);
    };
    if !selected.intersects(nego::SecurityProtocol::HYBRID | nego::SecurityProtocol::HYBRID_EX)
        || !connector.should_perform_security_upgrade()
    {
        return Err(REFUSED);
    }
    let (tcp, leftover) = framed.into_inner();
    if !leftover.is_empty() {
        return Err(REFUSED);
    }
    let tls = crate::pin::connect(tcp, &trust.certificate, &trust.name)
        .await
        .map_err(|_| Fail::End(Ended::CertificateChanged))?;
    // The verifier accepted only the pinned bytes; the leaf is compared again,
    // as sent, before any credential leaves this process.
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .ok_or(REFUSED)?
        .to_vec();
    if leaf != trust.certificate {
        return Err(Fail::End(Ended::CertificateChanged));
    }
    let server_public_key = crate::pin::public_key(&trust.certificate).map_err(|_| REFUSED)?;
    connector.mark_security_upgrade_as_done();
    if !connector.should_perform_credssp() {
        return Err(REFUSED);
    }
    let mut framed = ironrdp_tokio::TokioFramed::new(tls);
    let (sequence, ts_request) =
        CredsspSequence::init_for_connector(&connector, ServerName::from(trust.name.host()), server_public_key, None)
            .map_err(|_| REFUSED)?;
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
        return Err(REFUSED);
    }

    // The browser hears that TLS was selected, with the pinned certificate.
    let confirm = encode_vec(&X224(nego::ConnectionConfirm::Response {
        flags,
        protocol: nego::SecurityProtocol::SSL,
    }))
    .map_err(|_| REFUSED)?;
    let response = RDCleanPathPdu::new_response(trust.name.host().to_owned(), confirm, [trust.certificate.clone()])
        .and_then(|pdu| pdu.to_der())
        .map_err(|_| REFUSED)?;
    frame::write(gateway_out, Kind::Desktop, &response)
        .await
        .map_err(|_| Fail::Quiet)?;

    // The browser's Connect Initial, checked and re-encoded for Windows.
    let total = loop {
        if inbuf.len() >= 4 {
            if inbuf[0] != 3 {
                return Err(REFUSED);
            }
            break usize::from(u16::from_be_bytes([inbuf[2], inbuf[3]]));
        }
        browser_bytes(gateway_in, &mut inbuf, policy::MAX_CONNECT_INITIAL).await?;
    };
    if !(7..=policy::MAX_CONNECT_INITIAL).contains(&total) {
        return Err(REFUSED);
    }
    while inbuf.len() < total {
        browser_bytes(gateway_in, &mut inbuf, policy::MAX_CONNECT_INITIAL).await?;
    }
    let first: Vec<u8> = inbuf.drain(..total).collect();
    let (checked, names) = policy::connect_initial(&first, selected, clipboard).map_err(|_| REFUSED)?;
    Ok((tls, checked, names, inbuf))
}

async fn upstream<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    gateway: &mut R,
    windows: &mut W,
    splitter: &mut Splitter,
    channels: &RefCell<Channels>,
) -> Fail {
    loop {
        match frame::read(gateway).await {
            Ok((Kind::Browser, payload)) => {
                if let Err(fail) = pass_browser_bytes(&payload, splitter, channels, windows).await {
                    return fail;
                }
            }
            Ok(_) => return REFUSED,
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
        let Ok(pdus) = splitter.push(&chunk[..n]) else {
            return REFUSED;
        };
        out.clear();
        for (action, pdu) in &pdus {
            match channels.borrow_mut().server_pdu(*action, pdu) {
                Ok(Pass::Unchanged) => out.extend_from_slice(pdu),
                Ok(Pass::Instead(instead)) => instead.iter().for_each(|p| out.extend_from_slice(p)),
                Err(_) => return REFUSED,
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
    /// name and the password on two lines. CI's native lab and the test VM set
    /// it; elsewhere the test says so and passes.
    #[test]
    fn a_browser_reaches_the_desktop_through_the_proxy() {
        let Ok(spec) = std::env::var("KEYBASH_PROXY_TEST") else {
            eprintln!("KEYBASH_PROXY_TEST unset: no NLA server to reach");
            return;
        };
        let parts: Vec<&str> = spec.split(',').collect();
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
        run_async(async {
            let (mut to_proxy, mut proxy_in) = duplex(256 * 1024);
            let (mut proxy_out, mut from_proxy) = duplex(256 * 1024);
            let proxy = run(&mut proxy_in, &mut proxy_out, setup, &trust, target);
            let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
                tokio::select! {
                    fail = proxy => Err(format!("the proxy ended first: {fail:?}")),
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
            let setup = crate::setup::parse(&crate::setup::encode(
                "kb-account-name",
                "KB-DOMAIN",
                "kb-secret-word",
                false,
            ))
            .expect("setup");
            let trust = Trust {
                certificate: crate::pin::tests::certificate_der(),
                name: Name::ExactLeaf,
            };
            let (_, sent) = tokio::join!(run(&mut proxy_in, &mut proxy_out, setup, &trust, target), peer);
            for secret in ["kb-account-name", "KB-DOMAIN", "kb-secret-word", "mstshash"] {
                assert!(
                    !sent.windows(secret.len()).any(|w| w == secret.as_bytes()),
                    "{secret} crossed before TLS: {sent:?}"
                );
            }
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
            let setup = crate::setup::parse(&crate::setup::encode("u", "", "never-sent", false)).expect("setup");
            let trust = Trust {
                certificate: crate::pin::tests::certificate_der(),
                name: Name::ExactLeaf,
            };
            let (fail, ()) = tokio::join!(run(&mut proxy_in, &mut proxy_out, setup, &trust, target), peer);
            assert_eq!(fail, Fail::End(Ended::CertificateChanged));
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
                let setup = crate::setup::parse(&crate::setup::encode("u", "", "p", false)).expect("setup");
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
            for (what, request) in [
                (
                    "CredSSP from the browser",
                    with(x224(nego::SecurityProtocol::HYBRID), None),
                ),
                (
                    "TLS and CredSSP",
                    with(x224(nego::SecurityProtocol::SSL | nego::SecurityProtocol::HYBRID), None),
                ),
                (
                    "standard RDP security",
                    with(x224(nego::SecurityProtocol::empty()), None),
                ),
                (
                    "a preconnection blob",
                    with(x224(nego::SecurityProtocol::SSL), Some("blob".into())),
                ),
                ("not DER", b"GET / HTTP/1.1\r\n\r\n".to_vec()),
                ("cut short", good[..good.len() - 1].to_vec()),
            ] {
                let fail = if what == "cut short" {
                    // The rest never comes: the browser leaves.
                    let (mut to_proxy, mut proxy_in) = duplex(64 * 1024);
                    let (mut proxy_out, _from) = duplex(64 * 1024);
                    frame::write(&mut to_proxy, Kind::Browser, &request)
                        .await
                        .expect("write");
                    drop(to_proxy);
                    let setup = crate::setup::parse(&crate::setup::encode("u", "", "p", false)).expect("setup");
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
                assert!(
                    matches!(fail, Fail::End(Ended::Refused) | Fail::Quiet),
                    "{what}: {fail:?}"
                );
                if what != "cut short" {
                    assert_eq!(fail, Fail::End(Ended::Refused), "{what}");
                }
            }
        });
    }

    /// The NLA server named in `KEYBASH_PROXY_TEST`, if any (see above).
    fn live_server() -> Option<(Trust, Setup, SocketAddr)> {
        let spec = std::env::var("KEYBASH_PROXY_TEST").ok()?;
        let parts: Vec<&str> = spec.split(',').collect();
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
            assert_eq!(fail, Fail::End(Ended::Refused));
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
}
