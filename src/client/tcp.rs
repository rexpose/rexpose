use std::{error::Error, time::Duration};

use tokio::{io::{self, AsyncReadExt, AsyncWriteExt}, net::TcpStream, task::JoinHandle, time::timeout};
use tokio_rustls::{client::TlsStream, rustls::pki_types::ServerName};

use crate::{client::{Client, ConnectedClient, send_password}, common::{protocol::{AuthorizedConnection, Connectable, MgmtMessage, UnauthorizedConnection}, tcp_utils::forward_streams}};

const READ_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(1);
const TCP_CONNECTION_TIMEOUT: Duration = Duration::from_secs(2);


pub struct AuthorizedClient {
    client: ConnectedClient,
    forward_tasks: Vec<JoinHandle<()>>,
    password: String,
}

impl AuthorizedClient {
    async fn send_keep_alive(&mut self) -> io::Result<()> {
        log::debug!("sending keep alive message");
        timeout(WRITE_TIMEOUT, self.client.mgmt_stream.write_all(MgmtMessage::KeepAlive.message())).await??;
        return Ok(());
    }

    async fn open_forwarding_stream(&self) -> io::Result<TcpStream> {
        let stream = timeout(TCP_CONNECTION_TIMEOUT, TcpStream::connect(self.client.client.tcp_address())).await??;
        return Ok(stream);
    }

    async fn start_tls(&self, stream: TcpStream) -> Result<TlsStream<TcpStream>, std::io::Error> {
        let server_name = ServerName::try_from(self.client.client.server_address.clone()).unwrap();
        let tls_stream = self.client.tls_connector.connect(server_name, stream).await?;
        return Ok(tls_stream);
    }

    async fn open_local_forwarding_stream(&self, forwarded_port: &u16) -> io::Result<TcpStream> {
        let stream = timeout(TCP_CONNECTION_TIMEOUT, TcpStream::connect(format!("127.0.0.1:{}", forwarded_port))).await??;
        return Ok(stream);
    }
}


impl Connectable<AuthorizedClient, ConnectedClient> for Client {
    async fn connect(self) -> Result<ConnectedClient, Box<dyn Error>> {
        return self.connect_internal().await;
    }
}

impl UnauthorizedConnection<AuthorizedClient> for ConnectedClient {
    async fn authorize(mut self, password: &str) -> Result<AuthorizedClient, Box<dyn Error>> {
        self.authorize_internal(password).await?;
        return Ok(AuthorizedClient { client: self, forward_tasks: Vec::new(), password: password.to_string() })
    }
}



impl AuthorizedConnection for AuthorizedClient {
    async fn forward_communication(&mut self, forwarded_port: &u16, encrypted: bool) -> Result<(), Box<dyn Error>> {
        loop {
            let mut buf: [u8; 3] = [0;3];
            self.forward_tasks.retain(|tasks| !tasks.is_finished());
            let read_timeout_result = timeout(READ_TIMEOUT, self.client.mgmt_stream.read(&mut buf)).await;
            let read_result = match read_timeout_result {
                Ok(result) => result,
                Err(_) => {
                    self.send_keep_alive().await?;
                    continue;
                },
            };
            let read_count = read_result?;
            if read_count == 0 {
                log::info!("zero read, closing connection");
                return Ok(());
            }
            if buf.eq(MgmtMessage::KeepAlive.message()) {
                self.send_keep_alive().await?;
                continue;
            } else if !buf.eq(MgmtMessage::NotifyRequest.message()) {
                log::info!("received unknown message: {}", std::str::from_utf8(&buf).unwrap_or_default());
                continue;
            }
            log::debug!("Request notification received");
            let request_stream = match self.open_forwarding_stream().await {
                Ok(stream) => stream,
                Err(err) => {
                    log::warn!("error while opening remote forwarding stream: {}", err);
                    continue;
                },
            };
            log::debug!("request stream opened");
            let forward_stream = match self.open_local_forwarding_stream(forwarded_port).await {
                Ok(stream) => stream,
                Err(err) => {
                    log::warn!("error while opening local forwarding stream on port {}: {}", forwarded_port, err);
                    continue;
                },
            };
            log::debug!("local forwarding stream opened");
            let (join_handle_1, join_handle_2) = if encrypted {
                let mut tls_stream = match self.start_tls(request_stream).await {
                    Ok(stream) => stream,
                    Err(err) => {
                        log::warn!("failed to start tls: {}", err);
                        continue;
                    },
                };
                match send_password(&mut tls_stream, &self.password).await {
                    Ok(_) => {
                        log::debug!("password sent")
                    },
                    Err(err) => {
                        log::warn!("failed to send password: {}", err);
                        continue;
                    },
                }
                forward_streams(tls_stream, forward_stream)
            } else {
                forward_streams(request_stream, forward_stream)
            };
            self.forward_tasks.push(join_handle_1);
            self.forward_tasks.push(join_handle_2);
            self.send_keep_alive().await?;
        }
    }

    async fn shutdown(mut self) {
        let _ = self.client.mgmt_stream.shutdown().await;
        for task in self.forward_tasks {
            task.abort();
        }
    }
}