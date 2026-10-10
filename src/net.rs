//! Outbound HTTPS (OIDC, Resend, GitHub release checks, S3) using rustls/ring
//! with bundled webpki roots, so the binary works in a scratch image.
use std::sync::Arc;

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub fn rustls_client_config() -> rustls::ClientConfig {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()
}

pub fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .use_preconfigured_tls(rustls_client_config())
        .user_agent(concat!("excalidash-rs/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(std::time::Duration::from_secs(10))
        .pool_max_idle_per_host(1)
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("http client")
}

pub fn shared_tls_config() -> Arc<rustls::ClientConfig> {
    Arc::new(rustls_client_config())
}
