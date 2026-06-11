//! TLS certificate manager for curf.
//!
//! Supports multiple domains via SNI (Server Name Indication).
//! Each domain gets its own certificate; the right one is automatically
//! picked based on the TLS ClientHello.

use anyhow::{Context, Result};
use rustls::crypto::ring;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::fs::File;
use std::io::{BufReader, Seek};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

pub struct SslManager {
    domains: Vec<DomainCert>,
    acceptor: Option<TlsAcceptor>,
}

struct DomainCert {
    name: String,
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl SslManager {
    pub fn new() -> Self {
        Self {
            domains: Vec::new(),
            acceptor: None,
        }
    }

    /// Register a domain's certificate and key.
    pub fn add_domain(&mut self, domain: String, cert_path: &str, key_path: &str) -> Result<()> {
        let (certs, key) = load_cert_and_key(cert_path, key_path)
            .with_context(|| format!("Failed to load TLS materials for '{}'", domain))?;
        self.domains.push(DomainCert {
            name: domain,
            certs,
            key,
        });
        Ok(())
    }

    /// Build the SNI-aware TLS acceptor. Call once after all domains are added.
    pub fn build(&mut self) -> Result<()> {
        let mut resolver = ResolvesServerCertUsingSni::new();

        for d in &self.domains {
            let signing_key = ring::sign::any_supported_type(&d.key)
                .context("Unsupported or invalid private key")?;
            let ck = CertifiedKey::new(d.certs.clone(), signing_key);
            resolver
                .add(d.name.as_str(), ck)
                .with_context(|| format!("Failed to register cert for '{}'", d.name))?;
        }

        let mut cfg = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("Failed to configure TLS protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));

        // Advertise HTTP/2 and HTTP/1.1 via ALPN
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        self.acceptor = Some(TlsAcceptor::from(Arc::new(cfg)));
        Ok(())
    }

    pub fn has_domains(&self) -> bool {
        !self.domains.is_empty()
    }

    /// Returns the TLS acceptor. Panics if `build()` was not called first.
    pub fn acceptor(&self) -> &TlsAcceptor {
        self.acceptor
            .as_ref()
            .expect("SslManager: build() not called")
    }
}

// ─── Certificate loading helpers ─────────────────────────────────────────────

fn load_cert_and_key(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    // Load certificate chain
    let cert_file =
        File::open(cert_path).with_context(|| format!("Cannot open cert file '{}'", cert_path))?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in '{}'", cert_path);
    }

    // Load private key
    let key_file =
        File::open(key_path).with_context(|| format!("Cannot open key file '{}'", key_path))?;
    let mut key_reader = BufReader::new(key_file);
    let key = load_key(&mut key_reader)
        .with_context(|| format!("Failed to load private key from '{}'", key_path))?;

    Ok((certs, key))
}

fn load_key(reader: &mut BufReader<File>) -> Result<PrivateKeyDer<'static>> {
    // Try PKCS#8 first
    let pkcs8: Vec<_> = rustls_pemfile::pkcs8_private_keys(reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    if let Some(k) = pkcs8.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(k));
    }

    // Fall back to PKCS#1 (RSA)
    reader.seek(std::io::SeekFrom::Start(0))?;
    let rsa: Vec<_> = rustls_pemfile::rsa_private_keys(reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    if let Some(k) = rsa.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(k));
    }

    // Fall back to EC
    reader.seek(std::io::SeekFrom::Start(0))?;
    let ec: Vec<_> = rustls_pemfile::ec_private_keys(reader)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default();
    if let Some(k) = ec.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(k));
    }

    anyhow::bail!("No supported private key found (expected PKCS#8, PKCS#1, or EC)");
}
