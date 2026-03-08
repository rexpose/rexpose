use std::{error::Error, process::Stdio, time::Duration};

use tokio::{net::UdpSocket, process::{Child, Command}, sync::mpsc::Receiver, task::JoinHandle, time::{sleep, timeout}};

use crate::common::{get_unused_port, CERT_PATH, KEY_PATH, SECRET};

mod common;

#[tokio::test]
async fn forwarding_udp_unencrypted() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let (received, received_reflection) = forwarding_udp(false, false, test_string).await?;
    assert_eq!(received.as_str(), test_string);
    assert_eq!(received_reflection.as_str(), test_string);
    Ok(())
}

#[tokio::test]
async fn forwarding_udp_encrypted() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let (received, received_reflection) = forwarding_udp(true, true, test_string).await?;
    assert_eq!(received.as_str(), test_string);
    assert_eq!(received_reflection.as_str(), test_string);
    Ok(())
}

#[tokio::test]
async fn fail_unencrypted_client() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let result = forwarding_udp(true, false, test_string).await;
    assert_eq!(result.is_err(), true);
    Ok(())
}

#[tokio::test]
async fn fail_unencrypted_server() -> Result<(), Box<dyn Error>> {
    let test_string = "test";
    let result = forwarding_udp(false, true, test_string).await;
    assert_eq!(result.is_err(), true);
    Ok(())
}

async fn forwarding_udp(encrypted_server: bool, encrypted_client: bool, send: &str) -> Result<(String, String), Box<dyn Error>> {
    let client_port = get_unused_port().await?;
    let mgmt_port = get_unused_port().await?;
    let server_port = get_unused_port().await?;
    
    let mut server_handle = start_server(server_port, mgmt_port, encrypted_server)?;
    sleep(Duration::from_millis(500)).await;

    let mut client_cmd = Command::new(assert_cmd::cargo::cargo_bin_cmd!().get_program());
    client_cmd.arg("-P")
        .arg(SECRET)
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-p")
        .arg(client_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-a")
        .arg("localhost")
        .arg("-u")
        .kill_on_drop(true);
    if encrypted_client {
        client_cmd.arg("-e");
    }
    let mut client_handle = client_cmd.spawn()?;

    sleep(Duration::from_millis(500)).await;

    let (tx, rx) = tokio::sync::mpsc::channel::<String>(1);
    let client_join_handle = receive_and_reflect(client_port);
    let udp_send_handle = send_and_receive(rx, server_port);
    tx.send(send.to_string()).await?;
    let received = timeout(Duration::from_secs(1), client_join_handle).await??;
    let received_reflection = udp_send_handle.await.unwrap();

    server_handle.kill().await?;
    client_handle.kill().await?;
    Ok((received, received_reflection))
}

fn start_server(server_port: u16, mgmt_port: u16, encrypted: bool) -> Result<Child, Box<dyn Error>> {
    let mut server_cmd = Command::new(assert_cmd::cargo::cargo_bin_cmd!().get_program());
    server_cmd.arg("-s")
        .arg("-c")
        .arg(CERT_PATH)
        .arg("-k")
        .arg(KEY_PATH)
        .arg("-P")
        .arg(SECRET)
        .arg("-p")
        .arg(server_port.to_string())
        .arg("-m")
        .arg(mgmt_port.to_string())
        .arg("-u")
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if encrypted {
        server_cmd.arg("-e");
    }
    let server_handle = server_cmd.spawn()?;
    return Ok(server_handle)
}

fn send_and_receive(mut rx: Receiver<String>, port: u16) -> JoinHandle<String> {
    return tokio::spawn(async move {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to_send = rx.recv().await.unwrap();
        socket.send_to(to_send.as_bytes(), format!("127.0.0.1:{}", port)).await.unwrap();
        let mut buf: [u8; 256] = [0; 256];
        let (size, _) = socket.recv_from(&mut buf).await.unwrap();
        return std::str::from_utf8(&buf[..size]).unwrap().to_string();
    });
}

fn receive_and_reflect(port: u16) -> JoinHandle<String> {
    return tokio::spawn(async move {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).await.unwrap();
        let mut buf: [u8; 256] = [0; 256];
        let (size, addr) = socket.recv_from(&mut buf).await.unwrap();
        let received = std::str::from_utf8(&buf[..size]).unwrap().to_string();
        socket.send_to(&mut buf[..size], addr).await.unwrap();
        return received;
    });
}