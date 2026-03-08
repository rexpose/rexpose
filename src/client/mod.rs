pub mod udp;
pub mod tcp;

use std::{error::Error, sync::Arc, time::Duration};

use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream, rustls::{self, pki_types::{CertificateDer, ServerName, pem::PemObject}}};


const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const MGMT_STREAM_TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
pub const CONNECTION_RETRY_COUNT: u8 = 2;


pub struct Client {
    mgmt_port: u16,
    server_address: String,
    tls_connector: TlsConnector,
}

pub struct ConnectedClient {
    client: Client,
    mgmt_stream: TlsStream<TcpStream>,
}

impl ConnectedClient {
    async fn authorize_internal(&mut self, password: &str) -> Result<(), Box<dyn Error>> {
        return send_password(&mut self.mgmt_stream, &password).await
    }
}

pub async fn send_password(tls_stream: &mut TlsStream<TcpStream>, password: &str) -> Result<(), Box<dyn Error>> {
    timeout(WRITE_TIMEOUT, tls_stream.write_all(password.as_bytes())).await??;
    return Ok(())
}

impl Client {
    pub fn new(server_address: &str, mgmt_port: &u16, certificate_path: &Option<String>) -> Client {
        let mut root_store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
        if let Some(certificate_path) = certificate_path {
            let cert = CertificateDer::from_pem_file(certificate_path).unwrap();
            root_store.add(cert).unwrap();
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let tls_connector = TlsConnector::from(Arc::new(config));
        return Self { mgmt_port: *mgmt_port, server_address: server_address.to_string(), tls_connector: tls_connector }
    }

    pub fn tcp_address(&self) -> String {
        return format!("{}:{}", self.server_address, self.mgmt_port);
    }

    async fn connect_internal(self) -> Result<ConnectedClient, Box<dyn Error>> {
        let mgmt_stream = timeout(MGMT_STREAM_TCP_CONNECTION_TIMEOUT, TcpStream::connect(self.tcp_address())).await??;
        log::debug!("start TLS connection");
        let server_name = ServerName::try_from(self.server_address.clone()).unwrap();
        let tls_stream = timeout(TLS_CONNECTION_TIMEOUT, self.tls_connector.connect(server_name, mgmt_stream)).await??;
        log::debug!("TLS connection established");
        return Ok(ConnectedClient { client: self, mgmt_stream: tls_stream })
    }
}