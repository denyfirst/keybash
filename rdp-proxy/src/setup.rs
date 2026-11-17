//! The setup frame: what the gateway tells the proxy once, before anything
//! from the browser. Format 1, little endian:
//!
//! ```text
//! u8 version (1) | text user | text domain | text password | u8 flags
//! text = u16 length + UTF-8 bytes; flags bit 0 = the clipboard is allowed
//! ```
//!
//! The rules are those `rdplab.newNativePlan` applies today, so the same
//! credentials pass or fail on either path.

#[derive(Debug, PartialEq, Eq)]
pub struct SetupError;

pub struct Setup {
    pub user: String,
    pub domain: String,
    pub password: Secret,
    pub clipboard: bool,
}

/// A password: never printed, and overwritten when dropped. Copies made inside
/// IronRDP for CredSSP are outside its reach; the process ends with the session.
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[password]")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8, SetupError> {
        let (&b, rest) = self.0.split_first().ok_or(SetupError)?;
        self.0 = rest;
        Ok(b)
    }
    fn text(&mut self, most: usize) -> Result<String, SetupError> {
        let len = usize::from(u16::from_le_bytes([self.u8()?, self.u8()?]));
        if len > most || len > self.0.len() {
            return Err(SetupError);
        }
        let (bytes, rest) = self.0.split_at(len);
        self.0 = rest;
        let text = std::str::from_utf8(bytes).map_err(|_| SetupError)?;
        if text.contains('\0') {
            return Err(SetupError);
        }
        Ok(text.to_owned())
    }
}

pub fn parse(payload: &[u8]) -> Result<Setup, SetupError> {
    let mut r = Reader(payload);
    if r.u8()? != 1 {
        return Err(SetupError);
    }
    let user = r.text(128)?;
    let domain = r.text(128)?;
    let password = Secret(r.text(4096)?);
    let flags = r.u8()?;
    if user.is_empty() || password.as_str().is_empty() || flags & !1 != 0 || !r.0.is_empty() {
        return Err(SetupError);
    }
    Ok(Setup {
        user,
        domain,
        password,
        clipboard: flags & 1 == 1,
    })
}

#[cfg(test)]
pub fn encode(user: &str, domain: &str, password: &str, clipboard: bool) -> Vec<u8> {
    let mut out = vec![1u8];
    for text in [user, domain, password] {
        out.extend_from_slice(&u16::try_from(text.len()).expect("short").to_le_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out.push(u8::from(clipboard));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_setup_reads_back_as_written() {
        let s = parse(&encode("kbtest", "", "Pässwörd 🔑", true)).expect("valid");
        assert_eq!(
            (s.user.as_str(), s.domain.as_str(), s.password.as_str(), s.clipboard),
            ("kbtest", "", "Pässwörd 🔑", true)
        );
        let s = parse(&encode("u", "CORP", &"p".repeat(4096), false)).expect("valid");
        assert!(!s.clipboard && s.domain == "CORP");
        assert_eq!(format!("{:?}", s.password), "[password]");
    }

    #[test]
    fn anything_else_is_refused() {
        let good = encode("kbtest", "", "secret", false);
        let mut cases: Vec<Vec<u8>> = vec![
            vec![],
            [vec![2], good[1..].to_vec()].concat(),
            encode("", "", "secret", false),
            encode("kbtest", "", "", false),
            encode(&"u".repeat(129), "", "secret", false),
            encode("kbtest", &"d".repeat(129), "secret", false),
            encode("kbtest", "", &"p".repeat(4097), false),
            encode("kb\0test", "", "secret", false),
            encode("kbtest", "", "sec\0ret", false),
            [good.clone(), vec![0]].concat(),
            good[..good.len() - 1].to_vec(),
        ];
        let mut flags = good.clone();
        *flags.last_mut().expect("flags") = 2;
        cases.push(flags);
        let mut bad_utf8 = good.clone();
        bad_utf8[3] = 0xff;
        cases.push(bad_utf8);
        let mut long = good.clone();
        long[1] = 0xff;
        cases.push(long);
        for case in cases {
            assert!(parse(&case).is_err(), "{case:?}");
        }
    }
}
