use std::{
    error::Error as _,
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{Certificate, ClientBuilder, StatusCode};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme,
    StreamOwned,
};

use super::enforce_tls_validation;

// Public test-only CA, leaf and key, valid 2020-2100 for tls-updater.invalid.
// They are used only by the ephemeral loopback server below.
const CA_DER: &str = "MIIBfTCCASSgAwIBAgIUOS/KOpERxZKSqd/mFXUb+Fqj6aMwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAwwfU2hlbGxYIHVwZGF0ZXIgbG9vcGJhY2sgdGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowKjEoMCYGA1UEAwwfU2hlbGxYIHVwZGF0ZXIgbG9vcGJhY2sgdGVzdCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABPw+ShS4L/KxX4YPH+D6MGJCS2NrcLChsbmjsOEFk9wuQrQfAA1zhdoYQgKm6qJDoHqqs3voYVM+ijVwXqbawTyjJjAkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMCA0cAMEQCIHdJWRynZglfehevZ/M2KKef6/5KemCSU89OzfiI1r23AiBMci+KJRzEJPTu15Zql/IQvniuNDP0P/TUjM7wB+3/0g==";
const CERT_DER: &str = "MIIBojCCAUegAwIBAgIUFY7YhfrEUWz/s544PXXnXUzucDMwCgYIKoZIzj0EAwIwKjEoMCYGA1UEAwwfU2hlbGxYIHVwZGF0ZXIgbG9vcGJhY2sgdGVzdCBDQTAgFw0yMDAxMDEwMDAwMDBaGA8yMTAwMDEwMTAwMDAwMFowHjEcMBoGA1UEAwwTdGxzLXVwZGF0ZXIuaW52YWxpZDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAji3w2Wo2P4XnxjLksCD82zrG4yXUFBZuvCYW00CShXlSo7/I66WDfMD/vK7hPqNwjYayQU9az7jHJwTgSdq3ujVTBTMAwGA1UdEwEB/wQCMAAwHgYDVR0RBBcwFYITdGxzLXVwZGF0ZXIuaW52YWxpZDATBgNVHSUEDDAKBggrBgEFBQcDATAOBgNVHQ8BAf8EBAMCB4AwCgYIKoZIzj0EAwIDSQAwRgIhANrE97ZchhvWT4On29xcDwaHmQl6xDaKJ1n606p09A+OAiEA6PWSuvTdBTvP6uKZRkPoS+/ZpZsjnTAK4PjiXksl+F4=";
const KEY_DER: &str = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgIU8j4acIYAUSsNl6XvZ9YLubsB5Hb8Fehm1PoOcXRYqhRANCAAQI4t8NlqNj+F58Yy5LAg/Ns6xuMl1BQWbrwmFtNAkoV5UqO/yOulg3zA/7yu4T6jcI2GskFPWs+4xycE4Enat7";
const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, Debug)]
enum ClientHook {
    InsecureFlags,
    PreconfiguredTls,
}

#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn request(
    host: &str,
    trust_ca: bool,
    hook: ClientHook,
    enforce: bool,
) -> reqwest::Result<StatusCode> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let _ = rustls::crypto::ring::default_provider().install_default();
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(STANDARD.decode(CERT_DER).unwrap())],
            PrivatePkcs8KeyDer::from(STANDARD.decode(KEY_DER).unwrap()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "TLS client did not connect");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("TLS test listener failed: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(TIMEOUT)).unwrap();
        let connection = ServerConnection::new(Arc::new(server_config)).unwrap();
        let mut tls = StreamOwned::new(connection, stream);
        if let Ok(read) = tls.read(&mut [0_u8; 2048]) {
            assert!(read > 0, "TLS client closed without an HTTP request");
            tls.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .unwrap();
        }
    });

    let roots = if trust_ca {
        vec![Certificate::from_der(&STANDARD.decode(CA_DER).unwrap()).unwrap()]
    } else {
        vec![]
    };
    let builder = ClientBuilder::new()
        .no_proxy()
        .timeout(TIMEOUT)
        .resolve(host, address)
        .tls_certs_only(roots);
    let builder = match hook {
        ClientHook::InsecureFlags => builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true),
        ClientHook::PreconfiguredTls => builder.use_preconfigured_tls(
            ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
                .with_no_client_auth(),
        ),
    };
    let builder = if enforce {
        enforce_tls_validation(builder)
    } else {
        builder
    };
    let result = tauri::async_runtime::block_on(async {
        builder
            .build()?
            .get(format!("https://{host}:{}/", address.port()))
            .send()
            .await
            .map(|response| response.status())
    });
    server.join().unwrap();
    result
}

fn assert_certificate_rejected(error: reqwest::Error) {
    assert!(
        error.is_connect() && !error.is_timeout(),
        "expected TLS connection error: {error:?}"
    );
    let mut source = error.source();
    while let Some(current) = source {
        if matches!(
            current.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ) {
            return;
        }
        if let Some(io_error) = current.downcast_ref::<std::io::Error>() {
            if let Some(inner) = io_error.get_ref() {
                source = Some(inner);
                continue;
            }
        }
        source = current.source();
    }
    // Native TLS exposes platform-specific certificate error types. The
    // matching/trusted and insecure controls exercise the same fixture.
    #[cfg(not(any(feature = "native-tls", feature = "native-tls-vendored")))]
    panic!("expected certificate verification failure: {error:?}");
}

#[cfg(any(feature = "native-tls", feature = "native-tls-vendored"))]
#[test]
fn tls_native_client_identity_remains_supported_with_both_backends() {
    let certificate =
        format!("-----BEGIN CERTIFICATE-----\n{CERT_DER}\n-----END CERTIFICATE-----\n");
    let key = format!("-----BEGIN PRIVATE KEY-----\n{KEY_DER}\n-----END PRIVATE KEY-----\n");
    let identity =
        reqwest::Identity::from_pkcs8_pem(certificate.as_bytes(), key.as_bytes()).unwrap();
    enforce_tls_validation(ClientBuilder::new().use_native_tls().identity(identity))
        .build()
        .unwrap();
}

#[test]
fn tls_trusted_matching_endpoint_succeeds_after_client_hooks() {
    for hook in [ClientHook::InsecureFlags, ClientHook::PreconfiguredTls] {
        assert_eq!(
            request("tls-updater.invalid", true, hook, true).unwrap(),
            StatusCode::NO_CONTENT
        );
    }
}

#[test]
fn tls_untrusted_certificate_is_rejected_after_client_hooks() {
    for hook in [ClientHook::InsecureFlags, ClientHook::PreconfiguredTls] {
        assert_eq!(
            request("tls-updater.invalid", false, hook, false).unwrap(),
            StatusCode::NO_CONTENT,
            "insecure {hook:?} control must accept the fixture"
        );
        assert_certificate_rejected(request("tls-updater.invalid", false, hook, true).unwrap_err());
    }
}

#[test]
fn tls_wrong_hostname_is_rejected_after_client_hooks() {
    for hook in [ClientHook::InsecureFlags, ClientHook::PreconfiguredTls] {
        assert_eq!(
            request("wrong-updater.invalid", true, hook, false).unwrap(),
            StatusCode::NO_CONTENT,
            "insecure {hook:?} control must accept the fixture"
        );
        assert_certificate_rejected(
            request("wrong-updater.invalid", true, hook, true).unwrap_err(),
        );
    }
}
