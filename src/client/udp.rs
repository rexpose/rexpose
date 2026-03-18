#[cfg(test)]
use crate::client::udp::tests::SystemTimeMock as SystemTime;
#[cfg(not(test))]
use std::time::SystemTime;

use std::{collections::HashMap, error::Error, net::SocketAddr, sync::Arc, time::{Duration}};

use tokio::{io::{self, AsyncRead, AsyncWrite, AsyncWriteExt}, net::{TcpStream, UdpSocket}, sync::{Mutex, RwLock}, task::JoinHandle, time::{sleep, timeout}};
use tokio_rustls::rustls::pki_types::ServerName;

use crate::{client::{Client, ConnectedClient}, common::protocol::{addressed_udp_message, read_addressed_udp_message, AuthorizedConnection, Connectable, MgmtMessage, UnauthorizedConnection, UDP_BUFFER_SIZE}};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const UDP_LIFETIME: Duration = Duration::from_secs(60);
const UDP_KEEP_ALIVE_SLEEP: Duration = Duration::from_secs(10);


pub struct AuthorizedUdpClient {
    client: ConnectedClient,
}

pub struct UdpConnection {
    socket: Arc<UdpSocket>,
    read_handle: JoinHandle<()>,
    last_write_time: Arc<RwLock<SystemTime>>,
}

impl AuthorizedUdpClient {
    async fn send_periodic_keep_alive<W: AsyncWrite + Unpin>(writer: Arc<Mutex<W>>) -> io::Result<()> {
        loop {
            sleep(UDP_KEEP_ALIVE_SLEEP).await;
            let mut writer = writer.lock().await;
            timeout(WRITE_TIMEOUT, writer.write_all(MgmtMessage::KeepAlive.message())).await??;
        }
    }

    async fn lifetime_exceeded(last_write_time: &Arc<RwLock<SystemTime>>, last_read_time: &SystemTime) -> bool {
        let elapsed_read_time = match last_read_time.elapsed() {
            Ok(duration) => duration,
            Err(err) => {
                log::warn!("error while reading elapsed read time: {}", err);
                return false;
            },
        };
        if elapsed_read_time < UDP_LIFETIME {
            return false;
        }
        let elapsed_write_time = match last_write_time.read().await.elapsed() {
            Ok(duration) => duration,
            Err(err) => {
                log::warn!("error while reading elapsed write time: {}", err);
                return false;
            },
        };
        if elapsed_write_time < UDP_LIFETIME {
            return false;
        }
        log::debug!("lifetime of udp read time exceeded");
        return true;
    }

    async fn handle_udp_read<W: AsyncWrite + Unpin>(server_write: Arc<Mutex<W>>, udp_socket: Arc<UdpSocket>, last_write_time: Arc<RwLock<SystemTime>>, addr: SocketAddr) {
        let mut last_read_time = SystemTime::now();
        loop {
            let mut buf: [u8; UDP_BUFFER_SIZE] = [0;UDP_BUFFER_SIZE];
            let read_timeout_result = timeout(READ_TIMEOUT, udp_socket.recv(&mut buf)).await;
            let size = match read_timeout_result {
                Ok(Ok(size)) => size,
                Ok(Err(err)) => {
                    if AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await {
                        break;
                    }
                    log::warn!("error while forwarding udp: {}", err);
                    continue;
                }
                Err(_) => {
                    if AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await {
                        break;
                    }
                    continue;
                },
            };
            last_read_time = SystemTime::now();
            let mut server_write = server_write.lock().await;
            if let Err(err) = server_write.write_all(MgmtMessage::UdpStart.message()).await {
                log::error!("error while writing udp start to server: {}", err);
                break;
            }
            let to_send = match addressed_udp_message(addr, &buf[..size]) {
                Ok(message) => message,
                Err(err) => {
                    log::warn!("error while serializing udp message: {}", err);
                    continue;
                },
            };
            if let Err(err) = server_write.write_all(&to_send).await {
                log::error!("error while writing to server: {}", err);
            }
        }
    }

    async fn handle_udp_write<R: AsyncRead + Unpin, W: AsyncWrite + Unpin + Send + 'static>(mut server_read: R, server_write: Arc<Mutex<W>>, forwarded_port: u16) {
        let mut connections: HashMap<SocketAddr, UdpConnection> = HashMap::new();
        loop {
            connections.retain(|_, connection| connection.read_handle.is_finished());
            let (addr, msg) = match read_addressed_udp_message(&mut server_read).await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("error while reading msg stream: {}", err);
                    break;
                },
            };
            let connection = match connections.get(&addr) {
                Some(connection) => connection,
                None => {
                    let socket = match UdpSocket::bind("127.0.0.1:0").await {
                        Ok(socket) => Arc::new(socket),
                        Err(err) => {
                            log::warn!("failed to create UDP socket: {}", err);
                            continue;
                        },
                    };
                    if let Err(err) = socket.connect(format!("127.0.0.1:{}", forwarded_port)).await {
                        log::warn!("error to connect to udp socket: {}", err);
                        continue;
                    }
                    let last_write_time = Arc::new(RwLock::new(SystemTime::now()));
                    let read_handle = tokio::spawn(AuthorizedUdpClient::handle_udp_read(server_write.clone(), socket.clone(), last_write_time.clone(), addr));
                    connections.insert(addr, UdpConnection { socket: socket, read_handle: read_handle, last_write_time: last_write_time });
                    connections.get(&addr).unwrap()
                },
            };
            let mut last_write_time = connection.last_write_time.write().await;
            *last_write_time = SystemTime::now();
            if let Err(err) = connection.socket.send(&msg).await {
                log::warn!("error while sending udp message: {}", err);
                continue;
            }
        }
        for connection in connections {
            connection.1.read_handle.abort();
        }
    }
}

impl Connectable<AuthorizedUdpClient, ConnectedClient> for Client {
    async fn connect(self) -> Result<ConnectedClient, Box<dyn Error>> {
        return self.connect_internal().await;
    }
}

impl UnauthorizedConnection<AuthorizedUdpClient> for ConnectedClient {
    async fn authorize(mut self, password: &str) -> Result<AuthorizedUdpClient, Box<dyn Error>> {
        self.authorize_internal(password).await?;
        return Ok(AuthorizedUdpClient { client: self })
    }
}

impl AuthorizedConnection for AuthorizedUdpClient {
    async fn forward_communication(&mut self, forwarded_port: &u16, encrypted: bool) -> Result<(), Box<dyn Error>> {
        let server_stream = TcpStream::connect(self.client.client.tcp_address()).await?;

        let (write_handle, keep_alive_handle) = if encrypted {
        let server_name = ServerName::try_from(self.client.client.server_address.clone()).unwrap();
            let tls_stream = self.client.tls_connector.connect(server_name, server_stream).await?;
            let (server_read, server_write) = io::split(tls_stream);
            let server_write = Arc::new(Mutex::new(server_write));
            let write_handle = tokio::spawn(AuthorizedUdpClient::handle_udp_write(server_read, server_write.clone(), *forwarded_port));
            let keep_alive_handle = tokio::spawn(AuthorizedUdpClient::send_periodic_keep_alive(server_write.clone()));
            (write_handle, keep_alive_handle)
        } else {
            let (server_read, server_write) = server_stream.into_split();
            let server_write = Arc::new(Mutex::new(server_write));
            let write_handle = tokio::spawn(AuthorizedUdpClient::handle_udp_write(server_read, server_write.clone(), *forwarded_port));
            let keep_alive_handle = tokio::spawn(AuthorizedUdpClient::send_periodic_keep_alive(server_write.clone()));
            (write_handle, keep_alive_handle)
        };

        write_handle.await?;
        keep_alive_handle.abort();
        return Ok(());
    }

    async fn shutdown(self) {
        // nothing to do
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    pub struct SystemTimeMock {
        elapsed: Result<Duration, String>
    }

    impl SystemTimeMock {
        pub fn elapsed(&self) -> Result<Duration, String> {
            return self.elapsed.clone();
        }
        
        pub fn now() -> SystemTimeMock {
            return SystemTimeMock { elapsed: Ok(Duration::ZERO) }
        }
    }

    #[tokio::test]
    async fn lifetime_exceeded_write() {
        let last_write_time = Arc::new(RwLock::new(SystemTimeMock { elapsed: Ok(UDP_LIFETIME) }));
        let last_read_time = SystemTimeMock::now();
        let exceeded = AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await;
        assert_eq!(exceeded, false);
    }

    #[tokio::test]
    async fn lifetime_exceeded_read() {
        let last_write_time = Arc::new(RwLock::new(SystemTimeMock::now()));
        let last_read_time = SystemTimeMock{ elapsed: Ok(UDP_LIFETIME) };
        let exceeded = AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await;
        assert_eq!(exceeded, false);
    }

    #[tokio::test]
    async fn lifetime_exceeded_read_and_write() {
        let last_write_time = Arc::new(RwLock::new(SystemTimeMock { elapsed: Ok(UDP_LIFETIME) }));
        let last_read_time = SystemTimeMock{ elapsed: Ok(UDP_LIFETIME) };
        let exceeded = AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await;
        assert_eq!(exceeded, true);
    }

    #[tokio::test]
    async fn lifetime_exceeded_read_error() {
        let last_write_time = Arc::new(RwLock::new(SystemTimeMock { elapsed: Ok(UDP_LIFETIME) }));
        let last_read_time = SystemTimeMock{ elapsed: Err("".to_string()) };
        let exceeded = AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await;
        assert_eq!(exceeded, false);
    }

    #[tokio::test]
    async fn lifetime_exceeded_write_error() {
        let last_write_time = Arc::new(RwLock::new(SystemTimeMock { elapsed: Err("".to_string()) }));
        let last_read_time = SystemTimeMock{ elapsed: Ok(UDP_LIFETIME) };
        let exceeded = AuthorizedUdpClient::lifetime_exceeded(&last_write_time, &last_read_time).await;
        assert_eq!(exceeded, false);
    }
}