use std::{error::Error, time::Duration};

use tokio::{io::{self, AsyncWriteExt}, net::TcpListener, task::JoinHandle, time::timeout};

use crate::{common::{ip_extension::is_ip_private, protocol::{AuthorizedConnection, Connectable, MgmtMessage, UnauthorizedConnection}, tcp_utils::forward_streams}, server::{Server, UnauthorizedServer, WRITE_TIMEOUT, receive_and_test_pw}};

const IDLE_MGMT_STREAM_TIMEOUT: Duration = Duration::from_secs(20);
const WAIT_FOR_CONNECTIN_TIMEOUT: Duration = Duration::from_secs(2);
const TLS_ACCEPTOR_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_CLIENT_CONNECTION_TIMEOUTS: u32 = 10;

pub struct AuthorizedServer {
    server: UnauthorizedServer,
    forward_tasks: Vec<JoinHandle<()>>,
    password: String,
}

impl AuthorizedServer {
    pub async fn notify_new_request(&mut self) -> io::Result<()> {
        log::debug!("sending request notification");
        timeout(WRITE_TIMEOUT, self.server.mgmt_stream.write_all(MgmtMessage::NotifyRequest.message())).await??;
        return Ok(());
    }
}

impl Connectable<AuthorizedServer, UnauthorizedServer> for Server {
    async fn connect(self) -> Result<UnauthorizedServer, Box<dyn Error>> {
        return self.connect_internal().await;
    }
}


impl UnauthorizedConnection<AuthorizedServer> for UnauthorizedServer {
    async fn authorize(mut self, password: &str) -> Result<AuthorizedServer, Box<dyn Error>> {
        self.authorize_internal(password).await?;
        return Ok(AuthorizedServer { server: self, forward_tasks: Vec::new(), password: password.to_string() });
    }
}



impl AuthorizedConnection for AuthorizedServer {
    async fn forward_communication(&mut self, forwarded_port: &u16, encrpyted: bool) -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", forwarded_port)).await?;
        let mut client_connection_timeouts: u32 = 0;
        loop {
            if client_connection_timeouts >= MAX_CLIENT_CONNECTION_TIMEOUTS {
                log::warn!("Too many client connection timeouts");
                return Ok(())
            }
            self.forward_tasks.retain(|tasks| !tasks.is_finished());
            let (request_stream, _) = match timeout(IDLE_MGMT_STREAM_TIMEOUT, listener.accept()).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(err)) => {
                    log::info!("error while opening connection: {}", err);
                    continue;
                },
                Err(_) => {
                    if let Err(err) = self.server.test_mgmt_stream_connection().await {
                        log::warn!("mgmt stream broken: {}", err);
                        return Ok(())
                    }
                    continue;
                }
            };
            log::debug!("new connection on local forwarding port");
            if let Err(err) = self.notify_new_request().await {
                log::warn!("mgmt stream broken: {}", err);
                return Ok(())
            }
            loop {
                let forward_connection = match timeout(WAIT_FOR_CONNECTIN_TIMEOUT, self.server.mgmt_listener.accept()).await {
                    Ok(connection) => connection,
                    Err(_) => {
                        log::info!("timeout while waiting for forward connection");
                        client_connection_timeouts += 1;
                        break;
                    },
                };
                client_connection_timeouts = 0;
                let forward_stream = match forward_connection {
                    Ok((forward_stream,address)) => {
                        if is_ip_private(self.server.connected_address.ip()) || self.server.connected_address.ip().eq(&address.ip()) {
                            forward_stream
                        } else {
                            log::debug!("unknown forwarding address tried to connect: {}", address);
                            continue;
                        }
                    },
                    Err(err) => {
                        log::info!("forward connection error: {}", err);
                        break;
                    },
                };
                log::debug!("forward connection established");
                let (join_handle_1, join_handle_2) = if encrpyted {
                    let mut tls_stream = match timeout(TLS_ACCEPTOR_TIMEOUT, self.server.tls_acceptor.accept(forward_stream)).await {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(err )) => {
                            log::warn!("error while starting tls: {}", err);
                            continue;
                        },
                        Err(_) => {
                            log::warn!("timeout while starting tls");
                            continue;
                        },
                    };
                    match receive_and_test_pw(&mut tls_stream, &self.password).await {
                        Ok(_) => {
                            log::debug!("password validated");
                        },
                        Err(err) => {
                            log::warn!("error while receiving password: {}", err);
                            continue;
                        },
                    }
                    forward_streams(tls_stream, request_stream)
                } else {
                    forward_streams(request_stream, forward_stream)
                };
                self.forward_tasks.push(join_handle_1);
                self.forward_tasks.push(join_handle_2);
                break;
            }
        }
    }
    
    async fn shutdown(mut self) {
        let _ = self.server.mgmt_stream.shutdown().await;
        for join_handle in self.forward_tasks {
            join_handle.abort();
        }
    }
}