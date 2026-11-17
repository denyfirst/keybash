//! keybash-rdp-proxy: Keybash's credential-injecting RDP proxy
//! (docs/BROWSER-RDP-PROXY.md).
//!
//! The RDP worker starts it inside its sandbox, with the gateway's pipes as
//! standard input and output. It takes no argument, reads no environment, and
//! knows three fixed places: the bridge to Windows and the two trust files.

#![forbid(unsafe_code)]

mod channels;
mod clipboard;
mod config;
mod frame;
#[cfg(test)]
mod fuzz;
mod pin;
mod policy;
mod session;
mod setup;

use std::process::ExitCode;
use std::time::Duration;

use frame::{Ended, Kind};
use session::{Fail, Trust};

const BRIDGE: &str = "127.0.0.1:3390";
const PINNED: &str = "/run/keybash/approved.pem";
const NAME: &str = "/run/keybash/name";
/// The gateway sends the setup frame at once; a worker left waiting ends.
const SETUP_WAIT: Duration = Duration::from_secs(10);

/// The setup frame and the two trust files. Any fault refuses before Windows
/// is contacted.
async fn start<R: tokio::io::AsyncRead + Unpin>(gateway: &mut R) -> Result<(setup::Setup, Trust), Fail> {
    let (kind, payload) = tokio::time::timeout(SETUP_WAIT, frame::read(gateway))
        .await
        .map_err(|_| Fail::Quiet)??;
    if kind != Kind::Setup {
        return Err(Fail::End(Ended::Refused));
    }
    let setup = setup::parse(&payload).map_err(|_| Fail::End(Ended::Refused))?;
    let certificate = std::fs::read(PINNED).ok().and_then(|pem| pin::certificate(&pem).ok());
    let name = std::fs::read(NAME).ok().and_then(|raw| pin::name(&raw).ok());
    match (certificate, name) {
        (Some(certificate), Some(name)) => Ok((setup, Trust { certificate, name })),
        _ => Err(Fail::End(Ended::Refused)),
    }
}

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::FAILURE;
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
    else {
        return ExitCode::FAILURE;
    };
    let Ok(bridge) = BRIDGE.parse() else {
        return ExitCode::FAILURE;
    };
    runtime.block_on(async {
        let mut input = tokio::io::stdin();
        let mut output = tokio::io::stdout();
        let fail = match start(&mut input).await {
            Ok((setup, trust)) => session::run(&mut input, &mut output, setup, &trust, bridge).await,
            Err(fail) => fail,
        };
        if let Fail::End(code) = fail {
            let _ = frame::write(&mut output, Kind::Ended, &[code as u8]).await;
        }
    });
    ExitCode::SUCCESS
}
