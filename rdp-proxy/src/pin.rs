//! Windows' TLS identity: the pinned certificate, byte for byte, inside its
//! validity dates, and proven by the handshake signature made with its key.
//!
//! The certificate's fixed rules (not a CA, server use, key strength, the name)
//! were checked when it was approved (`internal/rdpcert`); the native worker's
//! `native/identity.c` holds the same line. IronRDP's own callback verifier is
//! not used: it asks the callback only after platform-root validation fails,
//! so a publicly trusted certificate would bypass the pin, and the sandbox has
//! no root store at all.

use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use tokio_rustls::rustls::pki_types::pem::PemObject as _;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{self, ClientConfig, DigitallySignedStruct, SignatureScheme};
use x509_cert::der::Decode as _;

/// Written in the name file for a server at a literal address, whose identity
/// is the pinned certificate alone; '@' is in no DNS name.
const EXACT_LEAF: &str = "@exact-leaf";

#[derive(Debug, PartialEq, Eq)]
pub struct PinError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Name {
    Dns(String),
    ExactLeaf,
}

impl Name {
    /// The name the server is addressed by in TLS and CredSSP. A literal
    /// address is reached through the bridge, as FreeRDP reaches it now.
    pub fn host(&self) -> &str {
        match self {
            Name::Dns(name) => name,
            Name::ExactLeaf => "127.0.0.1",
        }
    }
}

/// The name file: a lower-case DNS name, or exactly the exact-leaf mark.
pub fn name(raw: &[u8]) -> Result<Name, PinError> {
    let text = std::str::from_utf8(raw).map_err(|_| PinError)?;
    if text == EXACT_LEAF {
        return Ok(Name::ExactLeaf);
    }
    if text.is_empty()
        || text.len() > 253
        || !text
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    {
        return Err(PinError);
    }
    Ok(Name::Dns(text.to_owned()))
}

/// The pinned certificate: exactly one PEM certificate, nothing else.
pub fn certificate(pem: &[u8]) -> Result<Vec<u8>, PinError> {
    if pem.len() > 64 * 1024 || pem.windows(11).filter(|w| *w == b"-----BEGIN ").count() != 1 {
        return Err(PinError);
    }
    let der = CertificateDer::from_pem_slice(pem).map_err(|_| PinError)?;
    x509_cert::Certificate::from_der(der.as_ref()).map_err(|_| PinError)?;
    Ok(der.as_ref().to_vec())
}

/// The public key CredSSP binds to: the pinned certificate's.
pub fn public_key(der: &[u8]) -> Result<Vec<u8>, PinError> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| PinError)?;
    let key = cert.tbs_certificate.subject_public_key_info.subject_public_key;
    Ok(key.as_bytes().ok_or(PinError)?.to_vec())
}

fn validity(der: &[u8]) -> Result<(u64, u64), PinError> {
    let cert = x509_cert::Certificate::from_der(der).map_err(|_| PinError)?;
    let v = &cert.tbs_certificate.validity;
    Ok((
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    ))
}

#[derive(Debug)]
struct PinnedVerifier {
    pinned: Vec<u8>,
    not_before: u64,
    not_after: u64,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() != self.pinned.as_slice() {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        let now = now.as_secs();
        if now < self.not_before {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidYet));
        }
        if now > self.not_after {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Expired));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// TLS 1.2 or 1.3 with Windows, accepting only the pinned certificate. No
/// resumption, no key log, no client certificate.
pub fn client_config(pinned: &[u8]) -> Result<ClientConfig, PinError> {
    let (not_before, not_after) = validity(pinned)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedVerifier {
        pinned: pinned.to_vec(),
        not_before,
        not_after,
        provider: Arc::clone(&provider),
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| PinError)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

pub async fn connect(tcp: TcpStream, pinned: &[u8], name: &Name) -> std::io::Result<TlsStream<TcpStream>> {
    let config = client_config(pinned).map_err(|_| std::io::Error::other("pinned certificate"))?;
    let server_name = match name {
        Name::Dns(dns) => ServerName::try_from(dns.clone()).map_err(std::io::Error::other)?,
        // No SNI for a literal address; the verifier ignores the name either way.
        Name::ExactLeaf => ServerName::IpAddress(std::net::Ipv4Addr::LOCALHOST.into()),
    };
    tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(server_name, tcp)
        .await
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A self-signed certificate whose key was deleted when it was made: a pin
    /// no peer can ever match.
    const PINNED_ELSEWHERE: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDaTCCAlGgAwIBAgIUO+42hJoWvDH7mlDWzI/i5vz4cDQwDQYJKoZIhvcNAQEL
BQAwIDEeMBwGA1UEAwwVcGlubmVkLWVsc2V3aGVyZS50ZXN0MCAXDTI2MTExNzA3
MDMxMVoYDzIxMjYxMDI0MDcwMzExWjAgMR4wHAYDVQQDDBVwaW5uZWQtZWxzZXdo
ZXJlLnRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDPx0tY/4XG
LKMmwSRqr/Jkg/GFtR0X2XrMwEZQ+QuF2KwNG/r4Q1TQwrci0pvQt0AeWmyEOE72
A35l4mmi/CwdumLy1iyE640boITVZwrlLsKDXphTEbhgugjYFj8dnqU/l8fX6BTG
EBJaEwk0syqpfSzoBqC68vn2kHwaTjQBKRp68YHnRW1nGhuKMFkhndjT9ezeXFdL
+MeRuf2EY7L3HOPvfso06ppevlHJiojqkXmC/NHvze8Mzc2W75WkIXgBs6QQQMGI
VApuCZIGl60JBCAwRB7OXReCwFlg7PVYQFnCFytWtveJkGDVa+9yRxz4JkRtEScI
0qnI970dOz5JAgMBAAGjgZgwgZUwHQYDVR0OBBYEFN13GLMO+7RJ6H+rZgvOnjLf
Pnl8MB8GA1UdIwQYMBaAFN13GLMO+7RJ6H+rZgvOnjLfPnl8MA8GA1UdEwEB/wQF
MAMBAf8wIAYDVR0RBBkwF4IVcGlubmVkLWVsc2V3aGVyZS50ZXN0MAsGA1UdDwQE
AwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATANBgkqhkiG9w0BAQsFAAOCAQEAOI2h
fBnBt2BdyU4I0ku70q95UuhuVusk5HOwNHPn5YdMCgrL+Of0YG0FnIUdlKg0aCYv
U3gEa8s2o8PMF4CU/Xvfroj9IVrOuUFNd9zEk0G4x3oeurxK6kZDKI+4ir4QhbM2
v0x/m0ggPuCLEnxWnbIhnKBnq5BEz/7wy+ZrQAERmkgC5Zryzb7uUMPQH/Yg/2+D
w6WSUogER6zKH7UzMq1t6uowUPM/b2WbYmHCCDaQ68aodopHGSBfuaVXKmbOaumA
HCs9vEgJ+TZgPvE1wx0wgA8tyf7Fs51m50IWpwQNf/B4Vo9ppxNLwAqwoKkK3eyO
7P3+6IjJOvuigwhNOQ==
-----END CERTIFICATE-----
";

    pub(crate) fn certificate_der() -> Vec<u8> {
        certificate(PINNED_ELSEWHERE).expect("test certificate")
    }

    fn verifier(der: &[u8], not_before: u64, not_after: u64) -> PinnedVerifier {
        PinnedVerifier {
            pinned: der.to_vec(),
            not_before,
            not_after,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }

    #[test]
    fn only_the_pinned_bytes_within_their_dates_pass() {
        let der = certificate_der();
        let name = ServerName::try_from("ignored.test").expect("name");
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(2_000_000_000));
        let check = |v: &PinnedVerifier, cert: &[u8]| {
            v.verify_server_cert(&CertificateDer::from(cert.to_vec()), &[], &name, &[], now)
                .is_ok()
        };
        let (before, after) = validity(&der).expect("dates");
        assert!(before < 2_000_000_000 && after > 2_000_000_000);
        let v = verifier(&der, before, after);
        assert!(check(&v, &der));
        let mut other = der.clone();
        *other.last_mut().expect("bytes") ^= 1;
        assert!(!check(&v, &other), "a changed byte passed");
        assert!(!check(&v, &der[..der.len() - 1]), "a cut certificate passed");
        assert!(
            !check(&verifier(&der, before, 1_999_999_999), &der),
            "an expired pin passed"
        );
        assert!(
            !check(&verifier(&der, 2_000_000_001, after), &der),
            "a pin before its dates passed"
        );
        // The handshake signature is still checked with the certificate's key.
        assert!(!v.supported_verify_schemes().is_empty());
    }

    #[test]
    fn the_public_key_is_the_certificates() {
        let key = public_key(&certificate_der()).expect("key");
        // An RSA-2048 SubjectPublicKey: a DER sequence of the modulus and exponent.
        assert!(key.len() > 256 && key[0] == 0x30, "{}", key.len());
        assert!(public_key(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn the_name_file_is_a_dns_name_or_the_exact_mark() {
        assert_eq!(name(b"@exact-leaf"), Ok(Name::ExactLeaf));
        assert_eq!(name(b"rdp.example.test"), Ok(Name::Dns("rdp.example.test".into())));
        for bad in [
            &b""[..],
            b"@exact-leaf\n",
            b"@exact",
            b"RDP.example",
            b"a b",
            b"x\0",
            b"\xff",
            &[b'a'; 254][..],
            b"host_name",
        ] {
            assert!(name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_pinned_file_is_one_certificate() {
        assert!(certificate(b"").is_err());
        assert!(certificate(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n").is_err());
        assert!(certificate(&vec![b'a'; 64 * 1024 + 1]).is_err());
        assert_eq!(certificate(PINNED_ELSEWHERE).map(|d| d.len() > 800), Ok(true));
        let two = [PINNED_ELSEWHERE, PINNED_ELSEWHERE].concat();
        assert!(certificate(&two).is_err(), "two certificates passed");
        let as_key = String::from_utf8(PINNED_ELSEWHERE.to_vec())
            .expect("pem")
            .replace("CERTIFICATE", "PRIVATE KEY");
        assert!(certificate(as_key.as_bytes()).is_err(), "another PEM type passed");
    }
}
