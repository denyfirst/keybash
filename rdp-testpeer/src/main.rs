//! A synthetic RDP server for Keybash's tests, never shipped
//! (docs/BROWSER-RDP-PAGE.md, 3e): IronRDP's own server at the pinned commit,
//! with TLS and NLA. It takes one account, draws a grey desktop, and prints a
//! line for each desktop it opens, each key press and click it gets, and the
//! first pointer move, so a test sees a client and its input cross the whole
//! path.
//!
//!   keybash-rdp-testpeer ADDRESS CERTIFICATE.pem KEY.pem SECRET-FILE
//!
//! SECRET-FILE holds the user name and the password on two lines.

use std::io::Write as _;
use std::net::SocketAddr;
use std::num::{NonZeroU16, NonZeroUsize};
use std::path::Path;

use ironrdp_server::{
    BitmapUpdate, Credentials, DesktopSize, DisplayContext, DisplayUpdate, KeyboardEvent, MouseEvent, PixelFormat,
    RdpServer, RdpServerDisplay, RdpServerDisplayUpdates, RdpServerInputHandler, ServerResult, TlsIdentityCtx,
};

/// The desktop's size and its one colour, which a test looks for on the page.
const WIDTH: u16 = 1024;
const HEIGHT: u16 = 768;
const GREY: u8 = 160;

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "keybash-testpeer: {line}");
    let _ = out.flush();
}

#[derive(Default)]
struct Input {
    moved: bool,
}

impl RdpServerInputHandler for Input {
    fn keyboard(&mut self, event: KeyboardEvent) {
        if let KeyboardEvent::Pressed { code, extended } = event {
            say(&format!("key {}{code:#04x}", if extended { "e0 " } else { "" }));
        }
    }

    fn mouse(&mut self, event: MouseEvent) {
        match event {
            MouseEvent::Button {
                x, y, pressed: true, ..
            } => say(&format!("click {x} {y}")),
            MouseEvent::Move { .. } if !self.moved => {
                self.moved = true;
                say("pointer");
            }
            _ => {}
        }
    }
}

struct Display;

#[async_trait::async_trait]
impl RdpServerDisplay for Display {
    async fn size(&mut self) -> DesktopSize {
        DesktopSize {
            width: WIDTH,
            height: HEIGHT,
        }
    }

    async fn updates(&mut self, _: DisplayContext) -> ServerResult<Box<dyn RdpServerDisplayUpdates>> {
        // A client got through TLS, NLA and the connection sequence.
        say("desktop");
        Ok(Box::new(Grey { sent: false }))
    }
}

/// One whole grey picture, then nothing more.
struct Grey {
    sent: bool,
}

#[async_trait::async_trait]
impl RdpServerDisplayUpdates for Grey {
    async fn next_update(&mut self) -> ServerResult<Option<DisplayUpdate>> {
        if self.sent {
            std::future::pending::<()>().await;
        }
        self.sent = true;
        let mut data = vec![GREY; usize::from(WIDTH) * usize::from(HEIGHT) * 4];
        for alpha in data.iter_mut().skip(3).step_by(4) {
            *alpha = 0xff;
        }
        Ok(Some(DisplayUpdate::Bitmap(BitmapUpdate {
            x: 0,
            y: 0,
            width: NonZeroU16::new(WIDTH).expect("non-zero width"),
            height: NonZeroU16::new(HEIGHT).expect("non-zero height"),
            format: PixelFormat::BgrA32,
            data: data.into(),
            stride: NonZeroUsize::new(usize::from(WIDTH) * 4).expect("non-zero stride"),
        })))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, address, certificate, key, secret] = args.as_slice() else {
        eprintln!("usage: keybash-rdp-testpeer ADDRESS CERTIFICATE.pem KEY.pem SECRET-FILE");
        std::process::exit(2);
    };
    let address: SocketAddr = address.parse().expect("address");
    let secret = std::fs::read_to_string(secret).expect("secret file");
    let (username, password) = secret.trim_end_matches('\n').split_once('\n').expect("two lines");
    let identity = TlsIdentityCtx::init_from_paths(Path::new(certificate), Path::new(key)).expect("TLS identity");
    let acceptor = identity.make_acceptor().expect("TLS acceptor");
    let mut server = RdpServer::builder()
        .with_addr(address)
        .with_hybrid(acceptor, identity.pub_key)
        .with_input_handler(Input::default())
        .with_display_handler(Display)
        .build();
    server.set_credentials(Some(Credentials {
        username: username.to_owned(),
        password: password.to_owned(),
        domain: None,
    }));
    Box::pin(server.run()).await.expect("server");
}
