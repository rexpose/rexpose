use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

pub fn import_cert_chain(certificate_path: &str) -> Vec<CertificateDer<'static>> {
    return CertificateDer::pem_file_iter(certificate_path)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

pub fn import_private_key(key_path: &str) -> PrivateKeyDer<'static> {
    return PrivateKeyDer::from_pem_file(key_path).unwrap();
}