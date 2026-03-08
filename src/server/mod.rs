pub mod tcp;
pub mod udp;

use std::{error::Error, fmt, net::SocketAddr, sync::Arc, time::Duration};

use tokio::{io::{self, AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::timeout};
use tokio_rustls::{TlsAcceptor, rustls::ServerConfig, server::TlsStream};

use crate::common::{keystore::{import_cert_chain, import_private_key}, protocol::{MGMT_MESSAGE_SIZE, MgmtMessage}};

pub const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const READ_TIMEOUT: Duration = Duration::from_secs(1);


pub struct Server {
    mgmt_port: u16,
    tls_acceptor: TlsAcceptor,
}

impl Server {
    pub fn new(key_path: &str, certificate_path: &str, mgmt_port: &u16) -> Server {
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(import_cert_chain(certificate_path), import_private_key(key_path));
        let tls_acceptor = TlsAcceptor::from(Arc::new(config.unwrap()));
        return Self { mgmt_port: *mgmt_port, tls_acceptor: tls_acceptor }
    }

    async fn connect_internal(self) -> Result<UnauthorizedServer, Box<dyn Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", self.mgmt_port)).await?;
        log::debug!("listening for client to connect");
        let (stream, address) = listener.accept().await?;
        log::debug!("client connected, starting tls connection");
        let tls_stream = self.tls_acceptor.accept(stream).await?;
        log::debug!("tls connection established");
        return Ok(UnauthorizedServer { mgmt_stream: tls_stream, mgmt_listener: listener, connected_address: address, server: self });
    }
}

pub struct UnauthorizedServer {
    server: Server,
    mgmt_stream: TlsStream<TcpStream>,
    mgmt_listener: TcpListener,
    connected_address: SocketAddr,
}

impl UnauthorizedServer {
    async fn authorize_internal(&mut self, password: &str) -> Result<(), Box<dyn Error>> {
        return receive_and_test_pw(&mut self.mgmt_stream, password).await;
    }

    async fn send_keep_alive(&mut self) -> io::Result<()> {
        log::debug!("sending keep alive message");
        timeout(WRITE_TIMEOUT, self.mgmt_stream.write_all(MgmtMessage::KeepAlive.message())).await??;
        return Ok(());
    }

    pub async fn test_mgmt_stream_connection(&mut self) -> Result<(), Box<dyn Error>> {
        self.send_keep_alive().await?;
        let mut buf: [u8; MGMT_MESSAGE_SIZE] = [0;MGMT_MESSAGE_SIZE];
        timeout(READ_TIMEOUT, self.mgmt_stream.read_exact(&mut buf)).await??;
        return Ok(());
    }
}

pub async fn receive_and_test_pw(tls_stream: &mut TlsStream<TcpStream>, password: &str) -> Result<(), Box<dyn Error>> {
    let mut pw_buf: [u8; 256] = [0; 256];
    let pw_read_size = timeout(READ_TIMEOUT, tls_stream.read(&mut pw_buf)).await??;
    if pw_read_size == 0 {
        return Err(Box::new(io::Error::new(std::io::ErrorKind::InvalidData, "Zero read, connection closing")));
    }
    if password.eq(std::str::from_utf8(&pw_buf.split(|byte| *byte == 0).next().unwrap_or_default()).unwrap_or_default()) {
        return Ok(());
    }
    return Err(Box::new(InvalidPassword {}));
}

#[derive(Debug, Clone)]
struct InvalidPassword;

impl fmt::Display for InvalidPassword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid password provided")
    }
}

impl Error for InvalidPassword {}
