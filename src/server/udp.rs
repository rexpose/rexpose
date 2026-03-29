use std::{error::Error, sync::{atomic::AtomicBool, Arc}};

use tokio::{io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt}, net::UdpSocket};

use crate::{common::protocol::{addressed_udp_message, read_addressed_udp_message, AuthorizedConnection, Connectable, MgmtMessage, UnauthorizedConnection, MGMT_MESSAGE_SIZE, UDP_BUFFER_SIZE}, server::{Server, UnauthorizedServer}};

pub struct AuthorizedUdpServer {
    server: UnauthorizedServer
}

impl Connectable<AuthorizedUdpServer, UnauthorizedServer> for Server {
    async fn connect(self) -> Result<UnauthorizedServer, Box<dyn Error>> {
        return self.connect_internal().await;
    }
}

impl UnauthorizedConnection<AuthorizedUdpServer> for UnauthorizedServer {
    async fn authorize(mut self, password: &str) -> Result<AuthorizedUdpServer, Box<dyn Error>> {
        self.authorize_internal(password).await?;
        return Ok(AuthorizedUdpServer { server: self });
    }
}

impl AuthorizedUdpServer {
    async fn handle_udp_write<R: AsyncRead + Unpin>(mut client_read: R, udp_socket: Arc<UdpSocket>, stop: Arc<AtomicBool>) {
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let mut msg_buf: [u8; MGMT_MESSAGE_SIZE] = [0; MGMT_MESSAGE_SIZE];
            if let Err(err) = client_read.read_exact(&mut msg_buf).await {
                log::error!("failed to read client stream: {}", err);
                break;
            }
            if !msg_buf.eq(MgmtMessage::UdpStart.message()) {
                log::debug!("not interested in received message");
                continue;
            }
            let (addr, msg) = match read_addressed_udp_message(&mut client_read).await {
                Ok(result) => {
                    log::debug!("udp message received");
                    result
                },
                Err(err) => {
                    log::error!("failed to read client udp message: {}", err);
                    break;
                },
            };
            match udp_socket.send_to(&msg, addr).await {
                Ok(size) => {
                    if size == 0 {
                        log::warn!("zero write, udp socket closed")
                    } else {
                        log::debug!("udp message sent");
                    }
                },
                Err(err) => {
                    log::warn!("failed to send udp msg: {}", err);
                },
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn handle_udp_read<W: AsyncWrite + Unpin>(mut client_write: W, udp_socket: Arc<UdpSocket>, stop: Arc<AtomicBool>) {
        loop {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let mut msg: [u8; UDP_BUFFER_SIZE] = [0; UDP_BUFFER_SIZE];
            let (size, addr) = match udp_socket.recv_from(&mut msg).await {
                Ok(result) => {
                    log::debug!("udp message received");
                    result
                },
                Err(err) => {
                    log::warn!("failed to read udp socket: {}", err);
                    continue;
                },
            };
            if size == 0 {
                log::warn!("received zero bytes");
                continue;
            }
            let msg = match addressed_udp_message(addr, &msg[..size]) {
                Ok(msg) => msg,
                Err(err) => {
                    log::error!("error while converting udp message to addressed tcp message: {}", err);
                    continue;
                },
            };
            if let Err(err) = client_write.write_all(&msg).await {
                log::error!("failed to send udp message to client: {}", err);
                break;
            }
            log::debug!("udp message transfered to client");
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}


impl AuthorizedConnection for AuthorizedUdpServer {
    async fn forward_communication(&mut self, forwarded_port: &u16, encrypted: bool) -> Result<(), Box<dyn Error>> {
        let (client_stream, _) = self.server.mgmt_listener.accept().await?;
        let udp_socket = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", forwarded_port)).await?);
        let stop = Arc::new(AtomicBool::new(false));

        let (read_handle, write_handle) = if encrypted {
            let tls_stream = self.server.tls_acceptor.accept(client_stream).await?;
            let (client_read, client_write) = io::split(tls_stream);
            let read_handle = tokio::spawn(AuthorizedUdpServer::handle_udp_read(client_write, udp_socket.clone(), stop.clone()));
            let write_handle = tokio::spawn(AuthorizedUdpServer::handle_udp_write(client_read, udp_socket.clone(), stop.clone()));
            (read_handle, write_handle)
        } else {
            let (client_read, client_write) = client_stream.into_split();
            let read_handle = tokio::spawn(AuthorizedUdpServer::handle_udp_read(client_write, udp_socket.clone(), stop.clone()));
            let write_handle = tokio::spawn(AuthorizedUdpServer::handle_udp_write(client_read, udp_socket.clone(), stop.clone()));
            (read_handle, write_handle)
        };

        read_handle.await?;
        write_handle.await?;

        return Ok(());
    }

    async fn shutdown(self) {
        todo!()
    }
}