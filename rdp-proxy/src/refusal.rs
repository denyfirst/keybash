//! Why the proxy refused a desktop, as fixed codes: the side that sent what it
//! does not accept, and what it was. Only the two codes cross to the gateway,
//! in the Ended frame (crate::frame); the gateway names them with the same
//! words (internal/rdplab/refusals.go) in one journal line. Nothing from the
//! session itself is ever part of a refusal: no clipboard text, no account, no
//! address, no byte that came from either side. The words themselves are for
//! the tests and the gateway's list; the proxy's binary holds only the codes.

/// Who sent what was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    /// The browser, through the gateway's socket.
    Browser = 1,
    /// Windows, through the bridge.
    Windows = 2,
    /// Keybash itself: the gateway's frames, the setup, the trust files, or
    /// the proxy's own state.
    Keybash = 3,
}

/// Declares the refusals: each a code, never reused, and its word.
macro_rules! refusals {
    ($($name:ident = $code:literal => $word:literal,)*) => {
        /// What was refused. The code is what crosses; the word is for people.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Refusal {
            $($name = $code,)*
        }

        #[cfg(test)]
        impl Refusal {
            pub const ALL: &[Refusal] = &[$(Refusal::$name,)*];

            pub fn word(self) -> &'static str {
                match self {
                    $(Refusal::$name => $word,)*
                }
            }
        }
    };
}

// The gateway's list (internal/rdplab/refusals.go) must match this one line
// for line; a Go test reads this file and compares. New refusals take the
// next code; a code is never given another meaning.
refusals! {
    PduFraming = 1 => "PDU framing",
    PduSize = 2 => "PDU size",
    McsFromWindows = 3 => "MCS from Windows",
    McsFromBrowser = 4 => "MCS from the browser",
    ChannelDataNotAllowed = 5 => "data on a channel not allowed",
    JoinNotAllowed = 6 => "joining a channel not allowed",
    NoAccount = 7 => "no account for the Client Info",
    ClientInfo = 8 => "Client Info",
    ClientInfoTooMuch = 9 => "Client Info asks for more than the desktop",
    NotX224Data = 10 => "not an X.224 data PDU",
    NotConnectResponse = 11 => "not an MCS Connect Response",
    ChannelNumbering = 12 => "channel numbering",
    StaticChannelNotAllowed = 13 => "static channel not allowed",
    ChannelChunk = 14 => "channel chunk",
    ChannelChunkOrder = 15 => "channel chunk order",
    DynamicChannelPdu = 16 => "dynamic channel PDU",
    ChannelName = 17 => "channel name",
    DynamicChannelReused = 18 => "dynamic channel reused",
    CreateResponse = 19 => "create response",
    DynamicChannelNotAllowed = 20 => "opening a dynamic channel not allowed",
    DisplayLayoutFragmented = 21 => "display layout fragmented or compressed",
    DynamicChannelNotOpen = 22 => "data on a dynamic channel not open",
    DynamicChannelCommand = 23 => "dynamic channel command",
    DisplayLayout = 24 => "display layout",
    DisplayLayoutOutOfBounds = 25 => "display layout outside the bounds",
    ClipboardChunk = 26 => "clipboard chunk",
    ClipboardChunkOrder = 27 => "clipboard chunk order",
    ClipboardTooLarge = 28 => "clipboard message too large",
    ClipboardLength = 29 => "clipboard message length",
    ClipboardCapabilities = 30 => "clipboard capabilities",
    ClipboardFormatList = 31 => "clipboard format list",
    ClipboardNotText = 32 => "clipboard request for anything but text",
    ClipboardUnanswered = 33 => "clipboard requests unanswered",
    ClipboardResponse = 34 => "clipboard response",
    ClipboardNotAllowed = 35 => "clipboard message not allowed",
    ClipboardBeforeOpen = 36 => "clipboard before Windows' is open",
    ClipboardUnasked = 37 => "clipboard data nobody asked for",
    ClipboardFormatName = 38 => "clipboard format name",
    ClipboardMessage = 39 => "clipboard message",
    ConnectInitialTooLarge = 40 => "Connect Initial too large",
    NotConnectInitial = 41 => "not an MCS Connect Initial",
    NotToldTls = 42 => "the browser must have been told TLS",
    DesktopSize = 43 => "desktop size outside the bounds",
    DeviceScale = 44 => "device scale factor",
    MonitorLayout = 45 => "monitor layout",
    Encode = 46 => "encode",
    RdcleanpathRequest = 47 => "RDCleanPath request",
    RdcleanpathTooLarge = 48 => "RDCleanPath request too large",
    ConnectionChange = 49 => "RDCleanPath request changes the connection",
    X224Request = 50 => "X.224 request",
    SecurityNotTls = 51 => "security other than TLS",
    X224Confirm = 52 => "X.224 confirm",
    NlaNotSelected = 53 => "NLA not selected",
    BytesBeforeTls = 54 => "bytes before TLS",
    Certificate = 55 => "certificate or TLS",
    BytesAfterNla = 56 => "bytes after NLA",
    ConnectInitial = 57 => "Connect Initial",
    HandshakeTooSlow = 58 => "handshake too slow",
    GatewayFrame = 59 => "gateway frame",
    Setup = 60 => "setup",
    TrustFiles = 61 => "trust files",
    Internal = 62 => "proxy internal",
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The codes run 1, 2, 3 and on with no gap (the compiler refuses a code given
    /// twice), so a code outside the list is never one the proxy sends.
    #[test]
    fn codes_are_dense_and_start_at_one() {
        for (at, refusal) in Refusal::ALL.iter().enumerate() {
            assert_eq!(usize::from(*refusal as u8), at + 1, "{refusal:?}");
        }
        assert!(Refusal::ALL.len() < usize::from(u8::MAX));
        for side in [Side::Browser, Side::Windows, Side::Keybash] {
            assert_ne!(side as u8, 0);
        }
    }

    /// Each word is one short line a journal can hold as it is: printable
    /// ASCII from a small set, no quote, no control character, and no two
    /// alike.
    #[test]
    fn words_are_short_fixed_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for refusal in Refusal::ALL {
            let word = refusal.word();
            assert!((1..=64).contains(&word.len()), "{word}");
            assert!(
                word.bytes().all(|b| b.is_ascii_alphanumeric() || b" .'-".contains(&b)),
                "{word}"
            );
            assert!(seen.insert(word), "{word} is given twice");
        }
    }
}
