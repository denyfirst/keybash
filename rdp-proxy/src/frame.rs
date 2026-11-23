//! Frames on the worker's pipes: a type byte, a 32-bit little-endian length
//! and the payload, at most `MAX_PAYLOAD` bytes, both ways.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Gateway to proxy, once, first: the credentials and the policy.
    Setup = 1,
    /// Gateway to proxy: one WebSocket binary message from the browser.
    Browser = 2,
    /// Proxy to gateway: bytes for the browser, one binary message.
    Desktop = 3,
    /// Proxy to gateway: why the session ended: one byte from `Ended`, or
    /// for a refusal three: `REFUSED`, the side and the refusal's code
    /// (crate::refusal). Fixed codes only, never bytes from the session.
    Ended = 4,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            1 => Self::Setup,
            2 => Self::Browser,
            3 => Self::Desktop,
            4 => Self::Ended,
            _ => return None,
        })
    }
}

/// Why a session ended other than by a refusal, as the gateway names it with
/// one fixed word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ended {
    /// Windows did not accept the stored user name or password, or refused
    /// the account (2 is kept for telling these apart).
    Credentials = 1,
    /// Windows could not be reached through the bridge.
    Unreachable = 3,
    /// Windows ended the session.
    Remote = 6,
}

/// The first byte of a refusal's Ended frame: something crossed the proxy
/// that it does not accept. The side and the refusal's code follow. 4, once a
/// certificate change, is not sent: that is a refusal by Windows now.
pub const REFUSED: u8 = 5;

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    /// The other side closed between frames.
    Closed,
    /// A frame of an unknown type, over the limit, or cut short.
    Malformed,
}

pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<(Kind, Vec<u8>), FrameError> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(FrameError::Closed),
        Err(_) => return Err(FrameError::Malformed),
    }
    r.read_exact(&mut head[1..]).await.map_err(|_| FrameError::Malformed)?;
    let kind = Kind::from_byte(head[0]).ok_or(FrameError::Malformed)?;
    let len =
        usize::try_from(u32::from_le_bytes([head[1], head[2], head[3], head[4]])).map_err(|_| FrameError::Malformed)?;
    if len > MAX_PAYLOAD {
        return Err(FrameError::Malformed);
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await.map_err(|_| FrameError::Malformed)?;
    Ok((kind, payload))
}

pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, kind: Kind, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len())
        .ok()
        .filter(|_| payload.len() <= MAX_PAYLOAD)
        .ok_or_else(|| std::io::Error::other("frame too large"))?;
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(kind as u8);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    w.write_all(&out).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn a_frame_reads_back_as_written() {
        run(async {
            let mut buf = Vec::new();
            write(&mut buf, Kind::Browser, b"hello").await.expect("write");
            write(&mut buf, Kind::Ended, &[REFUSED, 2, 31]).await.expect("write");
            write(&mut buf, Kind::Setup, &[]).await.expect("write");
            let mut r = buf.as_slice();
            assert_eq!(read(&mut r).await, Ok((Kind::Browser, b"hello".to_vec())));
            assert_eq!(read(&mut r).await, Ok((Kind::Ended, vec![5, 2, 31])));
            assert_eq!(read(&mut r).await, Ok((Kind::Setup, vec![])));
            assert_eq!(read(&mut r).await, Err(FrameError::Closed));
        });
    }

    #[test]
    fn unknown_oversized_and_cut_frames_are_refused() {
        run(async {
            let cases: Vec<Vec<u8>> = vec![
                vec![0, 0, 0, 0, 0],
                vec![9, 1, 0, 0, 0, 7],
                [
                    vec![2],
                    (u32::try_from(MAX_PAYLOAD).expect("small") + 1).to_le_bytes().to_vec(),
                ]
                .concat(),
                vec![2, 0xff, 0xff, 0xff, 0xff],
                vec![2, 4, 0, 0, 0, 1, 2],
                vec![2, 4, 0],
            ];
            for case in cases {
                let mut r = case.as_slice();
                assert_eq!(read(&mut r).await, Err(FrameError::Malformed), "{case:?}");
            }
            // One byte over the limit, with every payload byte present.
            let over = u32::try_from(MAX_PAYLOAD + 1).expect("small");
            let whole = [vec![2], over.to_le_bytes().to_vec(), vec![0; MAX_PAYLOAD + 1]].concat();
            assert_eq!(read(&mut whole.as_slice()).await, Err(FrameError::Malformed));
            let at_limit = [
                vec![2],
                u32::try_from(MAX_PAYLOAD).expect("small").to_le_bytes().to_vec(),
                vec![0; MAX_PAYLOAD],
            ]
            .concat();
            assert_eq!(
                read(&mut at_limit.as_slice()).await.map(|(k, p)| (k, p.len())),
                Ok((Kind::Browser, MAX_PAYLOAD))
            );
            let mut out = Vec::new();
            assert!(write(&mut out, Kind::Desktop, &vec![0; MAX_PAYLOAD + 1]).await.is_err());
            assert!(out.is_empty(), "an oversized frame was partly written");
        });
    }
}
